use crate::{
    attrs::Attrs,
    com_tree::ComTree,
    proof_data_structures::{ForestProof, ForestProvingKey},
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{constraints::TwoToOneCRHGadget, TwoToOneCRH},
};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;

#[cfg(test)]
use crate::proof_data_structures::ForestVerifyingKey;

/// Roots of a `ComForest`
pub struct ComForestRoots<ConstraintF, H>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
{
    pub roots: Vec<H::Output>,
    _marker: PhantomData<ConstraintF>,
}

impl<ConstraintF, H> Clone for ComForestRoots<ConstraintF, H>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
{
    fn clone(&self) -> Self {
        Self {
            roots: self.roots.clone(),
            _marker: PhantomData,
        }
    }
}

impl<ConstraintF, H> ComForestRoots<ConstraintF, H>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
{
    #[cfg(test)]
    pub(crate) fn verify_memb<E, A, AC, ACG, HG>(
        &self,
        vk: &ForestVerifyingKey<E, A, AC, ACG, H, HG>,
        proof: &ForestProof<E, A, AC, ACG, H, HG>,
        attrs_com: &AC::Output,
        member_root: &H::Output,
    ) -> Result<bool, SynthesisError>
    where
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        ACG: CommitmentGadget<AC, E::Fr>,
        AC: CommitmentScheme,
        AC::Output: ToConstraintField<ConstraintF>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let attr_com_input = attrs_com.to_field_elements().unwrap();
        let member_root_input = member_root.to_field_elements().unwrap();
        let roots_input = self.public_inputs();

        let all_inputs = [attr_com_input, member_root_input, roots_input].concat();
        ark_groth16::verify_proof(&vk.pvk, &proof.proof, &all_inputs)
    }

    pub(crate) fn public_inputs(&self) -> Vec<ConstraintF> {
        self.roots
            .iter()
            .flat_map(|t| t.to_field_elements().unwrap())
            .collect()
    }
}

/// A forest of commitment trees
pub struct ComForest<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    pub trees: Vec<ComTree<ConstraintF, H, AC>>,
}

impl<ConstraintF, H, AC> ComForest<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Proves that the given attribute commitment is at the specified tree index
    pub fn prove_membership<R, E, A, ACG, HG>(
        &self,
        rng: &mut R,
        pk: &ForestProvingKey<E, A, AC, ACG, H, HG>,
        member_root: H::Output,
        attrs_com: AC::Output,
    ) -> Result<ForestProof<E, A, AC, ACG, H, HG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        ACG: CommitmentGadget<AC, E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let roots: Vec<H::Output> = self.trees.iter().map(ComTree::root).collect();
        let prover = ForestMembershipProver::<E::Fr, AC, ACG, H, HG> {
            roots,
            attrs_com,
            member_root,
            _marker: PhantomData,
        };

        let proof = ark_groth16::create_random_proof(prover, &pk.pk, rng)?;
        Ok(ForestProof {
            proof,
            _marker: PhantomData,
        })
    }

    pub fn roots(&self) -> ComForestRoots<ConstraintF, H> {
        let roots = self.trees.iter().map(ComTree::root).collect();
        ComForestRoots {
            roots,
            _marker: PhantomData,
        }
    }
}

/// Proves that the given attribute commitment is at the specified tree index
pub fn gen_forest_memb_crs<R, E, A, AC, ACG, H, HG>(
    rng: &mut R,
    num_trees: usize,
) -> Result<ForestProvingKey<E, A, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let roots = vec![H::Output::default(); num_trees];
    let attrs_com = AC::Output::default();
    let member_root = H::Output::default();
    let prover = ForestMembershipProver::<E::Fr, AC, ACG, H, HG> {
        roots,
        attrs_com,
        member_root,
        _marker: PhantomData,
    };

    let pk = ark_groth16::generate_random_parameters(prover, rng)?;
    Ok(ForestProvingKey {
        pk,
        _marker: PhantomData,
    })
}

struct ForestMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    // Public inputs
    roots: Vec<H::Output>,

    // Private inputs //
    // This is necessary for all proofs
    attrs_com: AC::Output,
    // The root that's the member of the forest
    member_root: H::Output,

    // Marker //
    _marker: PhantomData<(ConstraintF, AC, ACG, H, HG, HG)>,
}

impl<ConstraintF, AC, ACG, H, HG> ConstraintSynthesizer<ConstraintF>
    for ForestMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Witness the public variables. In ALL zeronym proofs, it's the commitment to the
        // attributes and the merkle root
        let _attrs_com = ACG::OutputVar::new_input(ns!(cs, "attrs com"), || Ok(self.attrs_com))?;
        let member_root = HG::OutputVar::new_input(ns!(cs, "root"), || Ok(self.member_root))?;

        // Witness the roots
        let roots = Vec::<HG::OutputVar>::new_input(ns!(cs, "roots"), || Ok(self.roots))?;

        // Assert that member_root equals one of the roots
        let mut is_member = Boolean::FALSE;
        for root in roots {
            is_member = is_member.or(&member_root.is_eq(&root)?)?;
        }

        is_member.enforce_equal(&Boolean::TRUE)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::test_util::{
        NameAndBirthYear, TestComScheme, TestComSchemeG, TestTreeH, TestTreeHG, MERKLE_CRH_PARAM,
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ff::UniformRand;

    pub(crate) fn random_tree<R: Rng>(rng: &mut R) -> ComTree<Fr, TestTreeH, TestComScheme> {
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), 32);
        let idx: u16 = rng.gen();
        let leaf = <<TestComScheme as CommitmentScheme>::Output as UniformRand>::rand(rng);
        tree.insert(idx as u64, &leaf);
        tree
    }

    /// Tests a predicate that returns true iff the given `NameAndBirthYear` is at least 21
    #[test]
    fn test_com_forest_proof() {
        let mut rng = ark_std::test_rng();
        let num_trees = 10;

        // Make a random commitment. This value doens't matter
        let attrs_com =
            <<TestComScheme as CommitmentScheme>::Output as UniformRand>::rand(&mut rng);

        // Generate the predicate circuit's CRS
        let pk = gen_forest_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComScheme,
            TestComSchemeG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, num_trees)
        .unwrap();

        // Make a bunch of trees with random elements inerted in them
        let trees: Vec<_> = core::iter::repeat_with(|| random_tree(&mut rng))
            .take(num_trees)
            .collect();
        let forest = ComForest { trees };

        // Start the memberhsip proof. Pick an arbitrary root
        let member_root = {
            let idx = rng.gen_range(0..num_trees);
            forest.trees[idx].root()
        };
        // Prove that the chosen root appears in the forest
        let proof = forest
            .prove_membership(&mut rng, &pk, member_root, attrs_com)
            .unwrap();

        // Verify

        let roots = forest.roots();
        let vk = pk.prepare_verifying_key();
        assert!(roots
            .verify_memb(&vk, &proof, &attrs_com, &member_root)
            .unwrap());
    }
}
