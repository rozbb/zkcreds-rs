use crate::{
    attrs::{Attrs, AttrsVar},
    identity_crh::{IdentityCRH, IdentityCRHGadget},
    proof_data_structures::{TreeProof, TreeProvingKey},
    sparse_merkle::{
        constraints::SparseMerkleTreePathVar, SparseMerkleTree, SparseMerkleTreePath,
        TwoToOneDigest,
    },
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{
        constraints::{CRHGadget, TwoToOneCRHGadget},
        TwoToOneCRH,
    },
    merkle_tree::{Config as TreeConfig, TwoToOneParam},
    Error as ArkError,
};
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, ToBytesGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

/// A sparse Merkle tree config which uses the identity function for leaf hashes (we don't need to
/// hash commitments)
struct ComTreeConfig<H: TwoToOneCRH>(H);

impl<H: TwoToOneCRH> TreeConfig for ComTreeConfig<H> {
    type LeafHash = IdentityCRH;
    type TwoToOneHash = H;
}

/// A Merkle tree of attribute commitments
pub struct ComTree<H, AC, MC>
where
    H: TwoToOneCRH,
    AC: CommitmentScheme,
    MC: CommitmentScheme,
{
    /// Parameters for the commitment of this tree's root
    merkle_com_params: MC::Parameters,

    /// The nonce for the commitment of this tree's root
    root_com_nonce: MC::Randomness,

    /// The tree's contents
    tree: SparseMerkleTree<ComTreeConfig<H>>,

    _marker: PhantomData<AC::Output>,
}

/// A commitment to a Merkle tree's root
pub struct RootCom<MC: CommitmentScheme>(MC::Output);

impl<H, AC, MC> ComTree<H, AC, MC>
where
    H: TwoToOneCRH,
    AC: CommitmentScheme,
    MC: CommitmentScheme,
{
    /// Returns a commitment to the tree's root
    pub fn root_com(&self) -> Result<RootCom<MC>, ArkError> {
        // Serialize the root and commit to it
        let root_bytes = {
            let mut buf = Vec::new();
            let root = self.tree.root();
            root.serialize(&mut buf)?;
            buf
        };
        MC::commit(&self.merkle_com_params, &root_bytes, &self.root_com_nonce).map(RootCom)
    }

    /// Generates the membership proving key for this tree
    pub fn gen_crs<R, E, HG, A, AV, ACG, MCG>(
        &self,
        rng: &mut R,
    ) -> Result<TreeProvingKey<E, A, AV, AC, ACG, MC, MCG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine,
        HG: TwoToOneCRHGadget<H, E::Fr>,
        A: Attrs<AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        ACG: CommitmentGadget<AC, E::Fr>,
        MCG: CommitmentGadget<MC, E::Fr>,
    {
        let prover: TreeMembershipProver<E::Fr, AC, ACG, MC, MCG, H, HG> = TreeMembershipProver {
            height: self.tree.height,
            two_to_one_param: self.tree.two_to_one_param.clone(),
            merkle_com_param: self.merkle_com_params.clone(),
            attrs_com: Default::default(),
            root: Default::default(),
            root_com: Default::default(),
            root_com_nonce: Default::default(),
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
    pub fn prove_membership<R, E, HG, A, AV, ACG, MCG>(
        &self,
        rng: &mut R,
        pk: &TreeProvingKey<E, A, AV, AC, ACG, MC, MCG>,
        idx: u64,
        attrs_com: AC::Output,
    ) -> Result<TreeProof<E, A, AV, AC, ACG, MC, MCG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine,
        HG: TwoToOneCRHGadget<H, E::Fr>,
        A: Attrs<AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        ACG: CommitmentGadget<AC, E::Fr>,
        MCG: CommitmentGadget<MC, E::Fr>,
    {
        // Get the root, its commitment, and the auth path of the given idx
        let root = self.tree.root();
        let root_com = self.root_com().expect("could not commit to root").0;
        let auth_path = self
            .tree
            .generate_proof(idx, &attrs_com)
            .expect("could not construct auth path");

        // Construct the prover with all the relevant info, and prove
        let prover: TreeMembershipProver<E::Fr, AC, ACG, MC, MCG, H, HG> = TreeMembershipProver {
            height: self.tree.height,
            two_to_one_param: self.tree.two_to_one_param.clone(),
            merkle_com_param: self.merkle_com_params.clone(),
            attrs_com,
            root,
            root_com,
            root_com_nonce: self.root_com_nonce.clone(),
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
struct TreeMembershipProver<ConstraintF, AC, ACG, MC, MCG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, ConstraintF>,
    H: TwoToOneCRH,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    // Constants //
    height: u32,
    two_to_one_param: TwoToOneParam<ComTreeConfig<H>>,
    merkle_com_param: MC::Parameters,

    // Public inputs //
    root: TwoToOneDigest<ComTreeConfig<H>>,

    // Private inputs //
    /// The leaf value
    attrs_com: AC::Output,
    /// A commitment to the root value
    root_com: MC::Output,
    /// The opening of the root commitment
    root_com_nonce: MC::Randomness,
    /// Merkle auth path of the leaf `attrs_com`
    auth_path: Option<SparseMerkleTreePath<ComTreeConfig<H>>>,

    // Marker //
    _marker: PhantomData<(ConstraintF, AC, ACG, MC, MCG, HG)>,
}

impl<ConstraintF, AC, ACG, MC, MCG, H, HG> ConstraintSynthesizer<ConstraintF>
    for TreeMembershipProver<ConstraintF, AC, ACG, MC, MCG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, ConstraintF>,
    H: TwoToOneCRH,
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
        let root_com_var =
            MCG::OutputVar::new_input(ns!(cs, "root com var"), || Ok(self.root_com))?;

        // Check that the root commitment is consistent
        let com_param_var =
            MCG::ParametersVar::new_constant(ns!(cs, "com param"), &self.merkle_com_param)?;
        let root_var = HG::OutputVar::new_input(ns!(cs, "root"), || Ok(&self.root))?;
        let root_com_nonce_var =
            MCG::RandomnessVar::new_input(ns!(cs, "root com nonce"), || Ok(&self.root_com_nonce))?;
        root_com_var.enforce_equal(&MCG::commit(
            &com_param_var,
            &root_var.to_bytes()?,
            &root_com_nonce_var,
        )?)?;

        // Now we do the tree membership proof. Input the two-to-one params
        let leaf_param_var =
            <IdentityCRHGadget as CRHGadget<IdentityCRH, _>>::ParametersVar::new_constant(
                ns!(cs, "identity param"),
                (),
            )?;
        let two_to_one_param_var =
            HG::ParametersVar::new_constant(ns!(cs, "two_to_one param"), &self.two_to_one_param)?;

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
            &two_to_one_param_var,
            &root_var,
            &attrs_com_var,
        )
    }
}
