use crate::{
    common::{AttrString, AttrStringVar},
    sparse_merkle::{constraints::SparseMerkleTreePathVar, SparseMerkleTreePath, TwoToOneDigest},
};
use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::constraints::{CRHGadget, TwoToOneCRHGadget},
    merkle_tree::{Config as TreeConfig, LeafParam, TwoToOneParam},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, ToBytesGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

/// A circuit that proves that a commitment to `attrs` appears in the merkle tree of height `height`
/// defined by root hash `root`.
pub struct ProofOfIssuanceCircuit<C, CG, P, ConstraintF, LeafH, TwoToOneH>
where
    C: CommitmentScheme,
    CG: CommitmentGadget<C, ConstraintF>,
    ConstraintF: PrimeField,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    P: TreeConfig,
{
    // Constants //
    height: u32,
    leaf_param: LeafParam<P>,
    two_to_one_param: TwoToOneParam<P>,
    com_param: C::Parameters,

    // Public inputs //
    root: TwoToOneDigest<P>,

    // Private inputs //
    /// The attrs
    attrs: Option<AttrString>,
    /// The opening of the commitment
    com_nonce: Option<C::Randomness>,
    /// Merkle auth path
    path: Option<SparseMerkleTreePath<P>>,

    // Marker //
    _marker: PhantomData<(ConstraintF, C, CG, LeafH, TwoToOneH)>,
}

impl<C, CG, P, ConstraintF, LeafH, TwoToOneH>
    ProofOfIssuanceCircuit<C, CG, P, ConstraintF, LeafH, TwoToOneH>
where
    C: CommitmentScheme,
    CG: CommitmentGadget<C, ConstraintF>,
    ConstraintF: PrimeField,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    P: TreeConfig,
{
    pub fn new(
        height: u32,
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
        com_param: C::Parameters,
        root: TwoToOneDigest<P>,
        opening: (AttrString, C::Randomness),
        path: SparseMerkleTreePath<P>,
    ) -> Self {
        ProofOfIssuanceCircuit {
            height,
            leaf_param,
            two_to_one_param,
            com_param,
            root,
            attrs: Some(opening.0),
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
        com_param: C::Parameters,
    ) -> Self {
        ProofOfIssuanceCircuit {
            height,
            leaf_param,
            two_to_one_param,
            com_param,
            root: Default::default(),
            attrs: None,
            com_nonce: None,
            path: None,
            _marker: PhantomData,
        }
    }
}

impl<C, CG, P, ConstraintF, LeafH, TwoToOneH> ConstraintSynthesizer<ConstraintF>
    for ProofOfIssuanceCircuit<C, CG, P, ConstraintF, LeafH, TwoToOneH>
where
    C: CommitmentScheme,
    CG: CommitmentGadget<C, ConstraintF>,
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
        let com_param_var = CG::ParametersVar::new_constant(ns!(cs, "com param"), &self.com_param)?;

        // Get the root as public input
        let root_var = TwoToOneH::OutputVar::new_input(ns!(cs, "root"), || Ok(&self.root))?;

        // Witness the attrs, its opening nonce, and the path
        let attrs_var = AttrStringVar::new_witness(ns!(cs, "attrs"), || {
            self.attrs.as_ref().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let com_nonce_var = CG::RandomnessVar::new_witness(ns!(cs, "attrs"), || {
            self.com_nonce
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let path_var = SparseMerkleTreePathVar::<_, LeafH, TwoToOneH, _>::new_witness(
            ns!(cs, "auth path"),
            || self.path.as_ref().ok_or(SynthesisError::AssignmentMissing),
            self.height,
        )?;

        // Compute the attrs commitment
        let com_var = CG::commit(&com_param_var, &attrs_var.to_bytes()?, &com_nonce_var)?;

        path_var.check_membership(
            ns!(cs, "check_membership").cs(),
            &leaf_param_var,
            &two_to_one_param_var,
            &root_var,
            &com_var,
        )
    }
}
