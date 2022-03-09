use crate::{
    attrs::{Attrs, AttrsVar},
    pred::PredicateChecker,
    proof_data_structures::{PredProof, PredVerifyingKey, TreeProof, TreeVerifyingKey},
    Com,
};

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{constraints::TwoToOneCRHGadget, TwoToOneCRH},
};
use ark_ec::PairingEngine;
use ark_ff::{ToConstraintField, Zero};
use ark_std::rand::{CryptoRng, Rng};
use groth_sahai_wrappers::{
    groth16::{prove_linked_g16_equations, verify_linked_g16_equations},
    groth_sahai::{
        prover::{Commit1, Commit2, EquProof},
        AbstractCrs, CRS,
    },
};

pub struct LinkProof<E: PairingEngine> {
    x_com: Commit1<E>,
    y_com: Commit2<E>,
    gs_proofs: Vec<EquProof<E>>,
}

pub struct LinkingKey<E: PairingEngine>(CRS<E>);

impl<E: PairingEngine> LinkingKey<E> {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> LinkingKey<E> {
        LinkingKey(CRS::generate_crs(rng))
    }

    pub fn link_proofs<R, P, A, AV, AC, ACG, H, HG>(
        &self,
        rng: &mut R,
        attrs_com: &Com<AC>,
        merkle_root: &H::Output,
        pred_checker: &P,
        tree_proof: &TreeProof<E, A, AC, ACG, H, HG>,
        tree_verif_key: &TreeVerifyingKey<E, A, AC, ACG, H, HG>,
        pred_proof: &PredProof<E, A, AV, AC, ACG, H, HG>,
        pred_verif_key: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    ) -> LinkProof<E>
    where
        R: Rng + CryptoRng,
        P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
        A: Attrs<E::Fr, AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        AC: CommitmentScheme,
        AC::Output: ToConstraintField<E::Fr>,
        ACG: CommitmentGadget<AC, E::Fr>,
        H: TwoToOneCRH,
        H::Output: ToConstraintField<E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        // Get the number of field elements that the two proofs have in common. This is just
        // |attrs_com| + |root|
        let common_inputs = {
            let attr_com_input = attrs_com.to_field_elements().unwrap();
            let root_input = merkle_root.to_field_elements().unwrap();
            &[attr_com_input, root_input].concat()
        };
        let num_common_inputs = common_inputs.len();
        let zeroed_common_inputs = vec![E::Fr::zero(); num_common_inputs];

        // Besides the attrs com and root, a predicate takes public input
        // pred_checker.public_inputs()
        let pred_public_input = [
            zeroed_common_inputs.as_slice(),
            &pred_checker.public_inputs(),
        ]
        .concat();
        // The tree proof's public inputs are just the attrs com and root
        let tree_public_input = zeroed_common_inputs;

        // Prepare the inputs
        let pred_prepared_inputs =
            ark_groth16::prepare_inputs(&pred_verif_key.pvk, &pred_public_input).unwrap();
        let tree_prepared_inputs =
            ark_groth16::prepare_inputs(&tree_verif_key.pvk, &tree_public_input).unwrap();

        let (x_com, y_com, gs_proofs) = prove_linked_g16_equations(
            &[
                (
                    &pred_proof.proof,
                    &pred_verif_key.pvk.vk,
                    &pred_prepared_inputs,
                ),
                (
                    &tree_proof.proof,
                    &tree_verif_key.pvk.vk,
                    &tree_prepared_inputs,
                ),
            ],
            common_inputs,
            &self.0,
            rng,
        );

        LinkProof {
            x_com,
            y_com,
            gs_proofs,
        }
    }

    #[must_use]
    pub fn verif_link_proof<P, A, AV, AC, ACG, H, HG>(
        &self,
        proof: &LinkProof<E>,
        pred_checker: &P,
        tree_verif_key: &TreeVerifyingKey<E, A, AC, ACG, H, HG>,
        pred_verif_key: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    ) -> bool
    where
        P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
        A: Attrs<E::Fr, AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        AC: CommitmentScheme,
        AC::Output: ToConstraintField<E::Fr>,
        ACG: CommitmentGadget<AC, E::Fr>,
        H: TwoToOneCRH,
        H::Output: ToConstraintField<E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        // Get the number of field elements that the two proofs have in common. This is just
        // |attrs_com| + |root|
        let num_common_inputs = {
            let attr_com_input = AC::Output::default().to_field_elements().unwrap();
            let root_input = H::Output::default().to_field_elements().unwrap();
            attr_com_input.len() + root_input.len()
        };
        let zeroed_common_inputs = vec![E::Fr::zero(); num_common_inputs];

        // Prepare the public input for the predicate proof. Besides the attrs com and root, a
        // predicate takes public input pred_checker.public_inputs()
        let pred_public_input = [
            zeroed_common_inputs.as_slice(),
            &pred_checker.public_inputs(),
        ]
        .concat();
        // The tree proof's public inputs are just the attrs com and root
        let tree_public_input = zeroed_common_inputs;

        // Prepare the inputs
        let pred_prepared_inputs =
            ark_groth16::prepare_inputs(&pred_verif_key.pvk, &pred_public_input).unwrap();
        let tree_prepared_inputs =
            ark_groth16::prepare_inputs(&tree_verif_key.pvk, &tree_public_input).unwrap();

        verify_linked_g16_equations(
            &[
                (&pred_verif_key.pvk.vk, &pred_prepared_inputs),
                (&tree_verif_key.pvk.vk, &tree_prepared_inputs),
            ],
            (&proof.x_com, &proof.y_com, &proof.gs_proofs),
            &self.0,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attrs::Attrs,
        com_tree::{gen_tree_memb_crs, verify_tree_memb, ComTree},
        pred::{gen_pred_crs, prove_pred, test::AgeProver, verify_pred},
        test_util::{
            NameAndBirthYear, TestComScheme, TestComSchemeG, TestTreeH, TestTreeHG,
            MERKLE_CRH_PARAM,
        },
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};

    /// Tests a predicate that returns true iff the given `NameAndBirthYear` is at least 21
    #[test]
    fn test_link() {
        let mut rng = ark_std::test_rng();
        let tree_height = 32;

        // Generate the predicate circuit's CRS
        let tree_proving_key = gen_tree_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComScheme,
            TestComSchemeG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, MERKLE_CRH_PARAM.clone(), tree_height)
        .unwrap();

        // Make a attribute to put in the tree
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        let person_com = person.commit();

        // Make a tree and "issue", i.e., put the person commitment in the tree at index 17
        let leaf_idx = 17;
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), tree_height);
        tree.insert(leaf_idx, &person_com);

        // The person can now prove membership in the tree. Calculate the root and prove wrt that
        // root.
        let merkle_root = tree.root();
        let tree_proof = tree
            .prove_membership(&mut rng, &tree_proving_key, leaf_idx, person_com)
            .unwrap();

        let tree_verif_key = tree_proving_key.prepare_verifying_key();
        assert!(verify_tree_memb(&tree_verif_key, &tree_proof, &person_com, &merkle_root).unwrap());

        // Prove a predicate

        // We choose that anyone born in 2001 or earlier satisfies our predicate
        let age_checker = AgeProver {
            threshold_birth_year: Fr::from(2001u16),
        };

        // Generate the predicate circuit's CRS
        let pred_pk = gen_pred_crs::<_, _, E, _, _, _, _, TestTreeH, TestTreeHG>(
            &mut rng,
            age_checker.clone(),
        )
        .unwrap();

        // Prove the predicate
        let pred_proof =
            prove_pred(&mut rng, &pred_pk, age_checker.clone(), person, merkle_root).unwrap();

        // Ordinarily we wouldn't be able to verify a predicate proof, since it requires knowledge
        // of the attribute commitment. But this is testing mode and we know this value, so let's
        // make sure the predicate proof verifies.
        let pred_verif_key = pred_pk.prepare_verifying_key();
        assert!(verify_pred(
            &pred_verif_key,
            &pred_proof,
            &age_checker,
            &person_com,
            &merkle_root
        )
        .unwrap());

        // Now link everything together
        let link_crs = LinkingKey::<E>::new(&mut rng);
        let link_proof = link_crs.link_proofs(
            &mut rng,
            &person_com,
            &merkle_root,
            &age_checker,
            &tree_proof,
            &tree_verif_key,
            &pred_proof,
            &pred_verif_key,
        );

        // Verify the link proof
        assert!(link_crs.verif_link_proof(
            &link_proof,
            &age_checker,
            &tree_verif_key,
            &pred_verif_key
        ));
    }
}
