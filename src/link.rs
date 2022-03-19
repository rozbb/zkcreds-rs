use crate::{
    attrs::{Attrs, AttrsVar},
    com_forest::{ComForest, ComForestRoots},
    pred::PredicateChecker,
    proof_data_structures::{
        ForestProof, ForestVerifyingKey, PredProof, PredVerifyingKey, TreeProof, TreeVerifyingKey,
    },
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

/// A CRS of a Groth-Sahai
pub struct GsCrs<E: PairingEngine>(CRS<E>);

impl<E: PairingEngine> GsCrs<E> {
    pub fn rand<R: Rng + CryptoRng>(rng: &mut R) -> GsCrs<E> {
        GsCrs(CRS::generate_crs(rng))
    }
}

impl<E: PairingEngine> Clone for GsCrs<E> {
    fn clone(&self) -> GsCrs<E> {
        GsCrs(CRS {
            u: self.0.u.clone(),
            v: self.0.v.clone(),
            g1_gen: self.0.g1_gen,
            g2_gen: self.0.g2_gen,
            gt_gen: self.0.gt_gen,
        })
    }
}

#[derive(Clone)]
pub struct PredPublicInputs<E: PairingEngine>(Vec<E::G1Projective>);

impl<E: PairingEngine> Default for PredPublicInputs<E> {
    fn default() -> PredPublicInputs<E> {
        PredPublicInputs(Vec::default())
    }
}

impl<E: PairingEngine> PredPublicInputs<E> {
    pub fn prepare_pred_checker<P, A, AV, AC, ACG, H, HG>(
        &mut self,
        pred_verif_key: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
        checker: &P,
    ) where
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
        // First set the common inputs to zero. This is filled in by the GS linking proof
        let attr_com_len = Com::<AC>::default().to_field_elements().unwrap().len();
        let root_len = H::Output::default().to_field_elements().unwrap().len();
        let common_inputs = vec![E::Fr::zero(); attr_com_len + root_len];

        // Now add the public inputs of this predicate
        let mut pred_public_input = common_inputs;
        pred_public_input.extend(checker.public_inputs());

        // Prepare the inputs and add them to the list of predicate inputs
        let prepared =
            ark_groth16::prepare_inputs(&pred_verif_key.pvk, &pred_public_input).unwrap();
        self.0.push(prepared);
    }
}

pub struct LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub gs_crs: GsCrs<E>,
    pub pred_inputs: PredPublicInputs<E>,
    pub com_forest_roots: ComForestRoots<E::Fr, H>,
    pub forest_verif_key: ForestVerifyingKey<E, A, AC, ACG, H, HG>,
    pub tree_verif_key: TreeVerifyingKey<E, A, AC, ACG, H, HG>,
    pub pred_verif_keys: Vec<PredVerifyingKey<E, A, AV, AC, ACG, H, HG>>,
}

impl<E, A, AV, AC, ACG, H, HG> Clone for LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            gs_crs: self.gs_crs.clone(),
            pred_inputs: self.pred_inputs.clone(),
            com_forest_roots: self.com_forest_roots.clone(),
            forest_verif_key: self.forest_verif_key.clone(),
            tree_verif_key: self.tree_verif_key.clone(),
            pred_verif_keys: self.pred_verif_keys.clone(),
        }
    }
}

pub struct LinkProofCtx<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub attrs_com: Com<AC>,
    pub merkle_root: H::Output,
    pub forest_proof: ForestProof<E, A, AC, ACG, H, HG>,
    pub tree_proof: TreeProof<E, A, AC, ACG, H, HG>,
    pub pred_proofs: Vec<PredProof<E, A, AV, AC, ACG, H, HG>>,
    pub vk: LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>,
}

pub fn link_proofs<R, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    ctx: &LinkProofCtx<E, A, AV, AC, ACG, H, HG>,
) -> LinkProof<E>
where
    R: Rng + CryptoRng,
    E: PairingEngine,
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
        let attr_com_input = ctx.attrs_com.to_field_elements().unwrap();
        let root_input = ctx.merkle_root.to_field_elements().unwrap();
        &[attr_com_input, root_input].concat()
    };
    let num_common_inputs = common_inputs.len();
    let zeroed_common_inputs = vec![E::Fr::zero(); num_common_inputs];

    // The tree proof's public inputs are just the attrs com and root
    let tree_public_input = zeroed_common_inputs.clone();
    // The forest's public inputs are the attrs com and root, plus all the roots of the forest
    let forest_public_input = [
        zeroed_common_inputs,
        ctx.vk.com_forest_roots.public_inputs(),
    ]
    .concat();

    // Prepare the inputs
    let tree_prepared_inputs =
        ark_groth16::prepare_inputs(&ctx.vk.tree_verif_key.pvk, &tree_public_input).unwrap();
    let forest_prepared_inputs =
        ark_groth16::prepare_inputs(&ctx.vk.forest_verif_key.pvk, &forest_public_input).unwrap();

    // Collect (proof, vk, prepared_inputs) for all our predicates
    let pred_triples = ctx
        .pred_proofs
        .iter()
        .zip(ctx.vk.pred_verif_keys.iter())
        .zip(ctx.vk.pred_inputs.0.iter())
        .map(|((proof, vk), input)| (&proof.proof, &vk.pvk.vk, input))
        .collect();

    // Collect (proof, vk, prepared_inputs) for the tree and forest
    let mut all_triples: Vec<(
        &ark_groth16::Proof<E>,
        &ark_groth16::VerifyingKey<E>,
        &E::G1Projective,
    )> = pred_triples;
    all_triples.push((
        &ctx.tree_proof.proof,
        &ctx.vk.tree_verif_key.pvk.vk,
        &tree_prepared_inputs,
    ));
    all_triples.push((
        &ctx.forest_proof.proof,
        &ctx.vk.forest_verif_key.pvk.vk,
        &forest_prepared_inputs,
    ));

    let (x_com, y_com, gs_proofs) =
        prove_linked_g16_equations(&all_triples, common_inputs, &ctx.vk.gs_crs.0, rng);

    LinkProof {
        x_com,
        y_com,
        gs_proofs,
    }
}

#[must_use]
pub fn verif_link_proof<E, A, AV, AC, ACG, H, HG>(
    proof: &LinkProof<E>,
    vk: &LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>,
) -> bool
where
    E: PairingEngine,
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

    // The tree proof's public inputs are just the attrs com and root
    let tree_public_input = zeroed_common_inputs.clone();
    // The forest's public inputs are the attrs com and root, plus all the roots of the forest
    let forest_public_input = [zeroed_common_inputs, vk.com_forest_roots.public_inputs()].concat();

    // Prepare the inputs
    let tree_prepared_inputs =
        ark_groth16::prepare_inputs(&vk.tree_verif_key.pvk, &tree_public_input).unwrap();
    let forest_prepared_inputs =
        ark_groth16::prepare_inputs(&vk.forest_verif_key.pvk, &forest_public_input).unwrap();

    // Collect (vk, prepared_inputs) for all our predicates
    let pred_tuples = vk
        .pred_verif_keys
        .iter()
        .zip(vk.pred_inputs.0.iter())
        .map(|(vk, input)| (&vk.pvk.vk, input))
        .collect();

    // Collect (vk, prepared_inputs) for the tree and forest
    let mut all_tuples: Vec<(&ark_groth16::VerifyingKey<E>, &E::G1Projective)> = pred_tuples;
    all_tuples.push((&vk.tree_verif_key.pvk.vk, &tree_prepared_inputs));
    all_tuples.push((&vk.forest_verif_key.pvk.vk, &forest_prepared_inputs));

    verify_linked_g16_equations(
        &all_tuples,
        (&proof.x_com, &proof.y_com, &proof.gs_proofs),
        &vk.gs_crs.0,
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attrs::Attrs,
        com_forest::{gen_forest_memb_crs, test::random_tree, ComForest},
        com_tree::{gen_tree_memb_crs, verify_tree_memb, ComTree},
        pred::{gen_pred_crs, prove_pred, test::AgeChecker, verify_pred},
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
        let auth_path = tree.insert(leaf_idx, &person_com);

        // The person can now prove membership in the tree. Calculate the root and prove wrt that
        // root.
        let merkle_root = tree.root();
        let tree_proof = auth_path
            .prove_membership(&mut rng, &tree_proving_key, &*MERKLE_CRH_PARAM, person_com)
            .unwrap();

        let tree_verif_key = tree_proving_key.prepare_verifying_key();
        assert!(verify_tree_memb(&tree_verif_key, &tree_proof, &person_com, &merkle_root).unwrap());

        // Prove a predicate

        // We choose that anyone born in 2001 or earlier satisfies our predicate
        let age_checker = AgeChecker {
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
            prove_pred(&mut rng, &pred_pk, age_checker.clone(), person, &auth_path).unwrap();

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

        // Prove that the tree is in the forest

        // Make a forest of 10 trees, with our tree occursing at a random index in the forest
        let num_trees = 10;
        let mut forest = ComForest {
            trees: core::iter::repeat_with(|| random_tree(&mut rng))
                .take(num_trees - 1)
                .collect(),
        };
        let rand_idx = rng.gen_range(0..num_trees);
        let root = tree.root();
        forest.trees.insert(rand_idx, tree);
        let roots = forest.roots();

        // Collect the predicate public inputs
        let mut pred_inputs = PredPublicInputs::default();
        pred_inputs.prepare_pred_checker(&pred_verif_key, &age_checker);

        // Generate the forest circuit's CRS
        let forest_pk = gen_forest_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComScheme,
            TestComSchemeG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, num_trees)
        .unwrap();
        let forest_proof = roots
            .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
            .unwrap();
        let forest_verif_key = forest_pk.prepare_verifying_key();
        assert!(roots
            .verify_memb(&forest_verif_key, &forest_proof, &person_com, &merkle_root)
            .unwrap());

        // Now link everything together
        let gs_crs = GsCrs::rand(&mut rng);
        let link_vk = LinkVerifyingKey {
            gs_crs,
            pred_inputs: pred_inputs.clone(),
            com_forest_roots: forest.roots(),
            forest_verif_key,
            tree_verif_key,
            pred_verif_keys: vec![pred_verif_key],
        };
        let link_ctx = LinkProofCtx {
            attrs_com: person_com,
            merkle_root: root,
            forest_proof,
            tree_proof,
            pred_proofs: vec![pred_proof],
            vk: link_vk.clone(),
        };
        let link_proof = link_proofs(&mut rng, &link_ctx);

        // Verify the link proof
        assert!(verif_link_proof(&link_proof, &link_vk));
    }
}
