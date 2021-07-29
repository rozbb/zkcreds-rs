use crate::{
    common::{Credential, CredentialVar},
    sparse_merkle::{constraints::SparseMerkleTreePathVar, SparseMerkleTreePath, TwoToOneDigest},
};
use core::marker::PhantomData;

use ark_crypto_primitives::{
    crh::constraints::{CRHGadget, TwoToOneCRHGadget},
    merkle_tree::{Config as TreeConfig, LeafParam, TwoToOneParam},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, ToBytesGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

/// The randomness used to commit to a credential
type ComNonce = Credential;

/// A circuit that proves that a commitment to `cred` appears in the merkle tree of height `height`
/// defined by root hash `root`.
pub struct ProofOfIssuanceCircuit<P, ConstraintF, LeafH, TwoToOneH>
where
    ConstraintF: PrimeField,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    P: TreeConfig,
{
    // Constants //
    height: u32,
    leaf_param: LeafParam<P>,
    two_to_one_param: TwoToOneParam<P>,

    // Public inputs //
    root: TwoToOneDigest<P>,

    // Private inputs //
    /// The credential
    cred: Option<Credential>,
    /// The opening of the commitment
    com_nonce: Option<ComNonce>,
    /// Merkle auth path
    path: Option<SparseMerkleTreePath<P>>,

    // Marker //
    _marker: PhantomData<(ConstraintF, LeafH, TwoToOneH)>,
}

impl<P, ConstraintF, LeafH, TwoToOneH> ProofOfIssuanceCircuit<P, ConstraintF, LeafH, TwoToOneH>
where
    ConstraintF: PrimeField,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    P: TreeConfig,
{
    pub fn new(
        height: u32,
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
        root: TwoToOneDigest<P>,
        opening: (Credential, ComNonce),
        path: SparseMerkleTreePath<P>,
    ) -> Self {
        ProofOfIssuanceCircuit {
            height,
            leaf_param,
            two_to_one_param,
            root,
            cred: Some(opening.0),
            com_nonce: Some(opening.1),
            path: Some(path),
            _marker: PhantomData,
        }
    }

    /// Makes a circuit with placeholder data. This is used for the purpose of CRS generation.
    pub fn new_placeholder(
        height: u32,
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
    ) -> Self {
        ProofOfIssuanceCircuit {
            height,
            leaf_param,
            two_to_one_param,
            root: Default::default(),
            cred: None,
            com_nonce: None,
            path: None,
            _marker: PhantomData,
        }
    }
}

impl<P, ConstraintF, LeafH, TwoToOneH> ConstraintSynthesizer<ConstraintF>
    for ProofOfIssuanceCircuit<P, ConstraintF, LeafH, TwoToOneH>
where
    ConstraintF: PrimeField,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    P: TreeConfig,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Input the parameters
        let leaf_param_var =
            LeafH::ParametersVar::new_constant(ns!(cs, "leaf param"), &self.leaf_param)?;
        let two_to_one_param_var = TwoToOneH::ParametersVar::new_constant(
            ns!(cs, "two_to_one param"),
            &self.two_to_one_param,
        )?;

        // Get the root as public input
        let root_var = TwoToOneH::OutputVar::new_input(ns!(cs, "root"), || Ok(&self.root))?;

        // Witness the credential, its opening nonce, and the path
        let cred_var = CredentialVar::new_witness(ns!(cs, "cred"), || {
            self.cred.as_ref().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let com_nonce_var = CredentialVar::new_witness(ns!(cs, "cred"), || {
            self.com_nonce
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let path_var = SparseMerkleTreePathVar::<_, LeafH, TwoToOneH, _>::new_witness(
            ns!(cs, "auth path"),
            || self.path.as_ref().ok_or(SynthesisError::AssignmentMissing),
            self.height,
        )?;

        // Compute the credential commitment
        let commitment_var = TwoToOneH::evaluate(
            &two_to_one_param_var,
            &cred_var.to_bytes()?,
            &com_nonce_var.to_bytes()?,
        )?;

        path_var.check_membership(
            ns!(cs, "check_membership").cs(),
            &leaf_param_var,
            &two_to_one_param_var,
            &root_var,
            &commitment_var,
        )
    }
}
