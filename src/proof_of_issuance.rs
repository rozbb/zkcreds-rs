use crate::{
    attrs::{Attrs, AttrsVar},
    identity_crh::{IdentityCRH, IdentityCRHGadget, UnitVar},
    proof_data_structures::{TreeProof, TreeProvingKey},
    sparse_merkle::{constraints::SparseMerkleTreePathVar, SparseMerkleTree, SparseMerkleTreePath},
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{constraints::TwoToOneCRHGadget, TwoToOneCRH},
    merkle_tree::{Config as TreeConfig, TwoToOneParam},
};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;

/// A sparse Merkle tree config which uses the identity function for leaf hashes (we don't need to
/// hash commitments)
struct ComTreeConfig<H: TwoToOneCRH>(H);

impl<H: TwoToOneCRH> TreeConfig for ComTreeConfig<H> {
    type LeafHash = IdentityCRH;
    type TwoToOneHash = H;
}

/// A Merkle tree of attribute commitments
pub struct ComTree<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Parameters for the hash function of the Merkle tree
    crh_params: H::Parameters,

    /// The tree's contents
    tree: SparseMerkleTree<ComTreeConfig<H>>,

    _marker: PhantomData<(ConstraintF, AC)>,
}

impl<ConstraintF, H, AC> ComTree<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Returns this tree's root
    pub fn root(&self) -> H::Output {
        self.tree.root()
    }

    /// Generates the membership proving key for this tree
    pub fn gen_crs<R, E, HG, A, AV, ACG, MCG>(
        &self,
        rng: &mut R,
    ) -> Result<TreeProvingKey<E, A, AV, AC, ACG, H, HG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine<Fr = ConstraintF>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
        A: Attrs<E::Fr, AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        ACG: CommitmentGadget<AC, E::Fr>,
    {
        let prover: TreeMembershipProver<E::Fr, AC, ACG, H, HG> = TreeMembershipProver {
            height: self.tree.height,
            crh_param: self.tree.two_to_one_param.clone(),
            attrs_com: Default::default(),
            root: Default::default(),
            //root: self.tree.root(),
            //root_com_nonce: self.nonce,
            auth_path: None,
            _marker: PhantomData,
        };
        let pk = ark_groth16::generate_random_parameters(prover, rng)?;
        Ok(TreeProvingKey {
            pk,
            _marker: PhantomData,
        })
    }

    /// Proves that the given attribute commitment is at the specified tree index
    pub fn prove_membership<R, E, A, AV, ACG, HG>(
        &self,
        rng: &mut R,
        pk: &TreeProvingKey<E, A, AV, AC, ACG, H, HG>,
        idx: u64,
        attrs_com: AC::Output,
    ) -> Result<TreeProof<E, A, AV, AC, ACG, H, HG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        ACG: CommitmentGadget<AC, E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        // Get the root, its commitment, and the auth path of the given idx
        let root = self.tree.root();
        let auth_path = self
            .tree
            .generate_proof(idx, &attrs_com)
            .expect("could not construct auth path");

        // Construct the prover with all the relevant info, and prove
        let prover: TreeMembershipProver<E::Fr, AC, ACG, H, HG> = TreeMembershipProver {
            height: self.tree.height,
            crh_param: self.tree.two_to_one_param.clone(),
            attrs_com,
            root,
            auth_path: Some(auth_path),
            _marker: PhantomData,
        };

        let proof = ark_groth16::create_random_proof(prover, &pk.pk, rng)?;
        Ok(TreeProof {
            proof,
            _marker: PhantomData,
        })
    }
}

/// A circuit that proves that a commitment to `attrs` appears in the Merkle tree of height `height`
/// defined by root hash `root`.
struct TreeMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    // Constants //
    height: u32,
    crh_param: TwoToOneParam<ComTreeConfig<H>>,

    // Public inputs //

    // Private inputs //
    /// The leaf value
    attrs_com: AC::Output,
    /// The tree root's value
    root: H::Output,
    /// Merkle auth path of the leaf `attrs_com`
    auth_path: Option<SparseMerkleTreePath<ComTreeConfig<H>>>,

    // Marker //
    _marker: PhantomData<(ConstraintF, AC, ACG, H, HG, HG)>,
}

impl<ConstraintF, AC, ACG, H, HG> ConstraintSynthesizer<ConstraintF>
    for TreeMembershipProver<ConstraintF, AC, ACG, H, HG>
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
        let attrs_com_var =
            ACG::OutputVar::new_input(ns!(cs, "attrs com var"), || Ok(self.attrs_com))?;
        let root_var = HG::OutputVar::new_input(ns!(cs, "root var"), || Ok(self.root))?;

        // Now we do the tree membership proof. Input the two-to-one params
        let crh_param_var =
            HG::ParametersVar::new_constant(ns!(cs, "two_to_one param"), &self.crh_param)?;
        // This is a placeholder value. We don't actually use leaf hashes
        let leaf_param_var = UnitVar::default();

        // Witness the path
        let path_var = SparseMerkleTreePathVar::<_, IdentityCRHGadget, HG, _>::new_witness(
            ns!(cs, "auth path"),
            || {
                self.auth_path
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)
            },
            self.height,
        )?;

        path_var.check_membership(
            ns!(cs, "check_membership").cs(),
            &leaf_param_var,
            &crh_param_var,
            &root_var,
            &attrs_com_var,
        )
    }
}
