//! Defines structures for holding Merkle forests, i.e., a set of Merkle trees. This is used in
//! credential issuance.

use crate::{
    attrs::Attrs,
    com_tree::ComTree,
    proof_data_structures::{ForestProof, ForestProvingKey, ForestVerifyingKey},
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
use linkg16::groth16;

#[derive(Clone, Copy)]
pub struct PreparedRoots<E: PairingEngine>(pub(crate) E::G1Projective);

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
    pub fn new(num_trees: usize) -> ComForestRoots<ConstraintF, H> {
        ComForestRoots {
            roots: vec![H::Output::default(); num_trees],
            _marker: PhantomData,
        }
    }

    pub fn prepare<E, A, AC, ACG, HG>(
        &self,
        vk: &ForestVerifyingKey<E, A, AC, ACG, H, HG>,
    ) -> Result<PreparedRoots<E>, SynthesisError>
    where
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        AC: CommitmentScheme,
        ACG: CommitmentGadget<AC, E::Fr>,
        AC::Output: ToConstraintField<E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        groth16::prepare_inputs(&vk.vk, &self.public_inputs()).map(PreparedRoots)
    }

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
        AC: CommitmentScheme,
        ACG: CommitmentGadget<AC, E::Fr>,
        AC::Output: ToConstraintField<ConstraintF>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let attr_com_input = attrs_com.to_field_elements().unwrap();
        let member_root_input = member_root.to_field_elements().unwrap();
        let roots_input = self.public_inputs();

        let all_inputs = [attr_com_input, member_root_input, roots_input].concat();
        groth16::verify_proof(&vk.vk, &proof.proof, &all_inputs)
    }

    pub fn public_inputs(&self) -> Vec<ConstraintF> {
        self.roots
            .iter()
            .flat_map(|t| t.to_field_elements().unwrap())
            .collect()
    }

    /// Proves that the given attribute commitment is at the specified tree index
    pub fn prove_membership<R, E, A, AC, ACG, HG>(
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
        AC: CommitmentScheme,
        ACG: CommitmentGadget<AC, E::Fr>,
        AC::Output: ToConstraintField<ConstraintF>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let prover = ForestMembershipProver::<E::Fr, AC, ACG, H, HG> {
            roots: self.roots.clone(),
            attrs_com,
            member_root,
            _marker: PhantomData,
        };

        let proof = groth16::create_random_proof(prover, &pk.pk, rng)?;
        Ok(ForestProof {
            proof,
            _marker: PhantomData,
        })
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

    let pk = groth16::generate_random_parameters(prover, rng)?;
    Ok(ForestProvingKey {
        pk,
        _marker: PhantomData,
    })
}

pub struct ForestMembershipProver<ConstraintF, AC, ACG, H, HG>
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
    pub roots: Vec<H::Output>,

    // Private inputs //
    // This is necessary for all proofs
    pub attrs_com: AC::Output,
    // The root that's the member of the forest
    pub member_root: H::Output,

    // Marker //
    pub _marker: PhantomData<(ConstraintF, AC, ACG, H, HG, HG)>,
}

impl<ConstraintF, AC, ACG, H, HG> ForestMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    pub fn circuit(
        &self,
        member_root: &HG::OutputVar,
        all_roots: &[HG::OutputVar],
    ) -> Result<(), SynthesisError> {
        // Assert that member_root equals one of the roots
        let mut is_member = Boolean::FALSE;
        for root in all_roots {
            is_member = is_member.or(&member_root.is_eq(root)?)?;
        }

        is_member.enforce_equal(&Boolean::TRUE)
    }
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
        // Witness the public variables. In ALL zkcreds proofs, it's the commitment to the
        // attributes and the merkle root
        let _attrs_com =
            ACG::OutputVar::new_input(ns!(cs, "attrs com"), || Ok(self.attrs_com.clone()))?;
        let member_root =
            HG::OutputVar::new_input(ns!(cs, "root"), || Ok(self.member_root.clone()))?;

        // Witness the roots
        let all_roots =
            Vec::<HG::OutputVar>::new_input(ns!(cs, "roots"), || Ok(self.roots.clone()))?;

        self.circuit(&member_root, &all_roots)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::test_util::{
        NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG,
        MERKLE_CRH_PARAM,
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ff::UniformRand;

    pub(crate) fn random_tree<R: Rng>(
        rng: &mut R,
    ) -> ComTree<Fr, TestTreeH, TestComSchemePedersen> {
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), 32);
        let idx: u16 = rng.gen();
        let leaf = <<TestComSchemePedersen as CommitmentScheme>::Output as UniformRand>::rand(rng);
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
            <<TestComSchemePedersen as CommitmentScheme>::Output as UniformRand>::rand(&mut rng);

        // Generate the predicate circuit's CRS
        let pk = gen_forest_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComSchemePedersen,
            TestComSchemePedersenG,
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
        // Collect the roots. We don't need the whole forest in order to compute a proof
        let roots = forest.roots();

        // Prove that the chosen root appears in the forest
        let proof = roots
            .prove_membership(&mut rng, &pk, member_root, attrs_com)
            .unwrap();

        // Verify

        let vk = pk.prepare_verifying_key();
        assert!(roots
            .verify_memb(&vk, &proof, &attrs_com, &member_root)
            .unwrap());
    }
}
