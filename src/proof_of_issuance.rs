use crate::{
    attrs::{Attrs, AttrsVar},
    common::{AttrString, AttrStringVar},
    pred::{PredicateChecker, PredicateProver},
    proof_data_structures::{PredProvingKey, TreeProvingKey},
    sparse_merkle::{
        constraints::SparseMerkleTreePathVar, SparseMerkleTree, SparseMerkleTreePath,
        TwoToOneDigest,
    },
};

use core::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{
        constraints::{CRHGadget, TwoToOneCRHGadget},
        TwoToOneCRH, CRH,
    },
    merkle_tree::{Config as TreeConfig, LeafParam, TwoToOneParam},
    Error as ArkError,
};
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar, ToBytesGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

// The unit type for circuit variables. This contains no data.
#[derive(Clone, Debug, Default)]
pub struct UnitVar<ConstraintF: PrimeField>(PhantomData<ConstraintF>);

impl<ConstraintF: PrimeField> AllocVar<(), ConstraintF> for UnitVar<ConstraintF> {
    // Allocates 32 UInt8s
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(UnitVar(PhantomData))
    }
}

/// A helper implementation. This CRH is the identity function on its input
struct IdentityCRH;
impl CRH for IdentityCRH {
    /// This value doesn't matter. We return everything no matter what
    const INPUT_SIZE_BITS: usize = 0;

    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, ArkError> {
        Ok(())
    }

    fn evaluate(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, ArkError> {
        Ok(input.to_vec())
    }
}

#[derive(Clone, Debug)]
struct Bytestring<ConstraintF: PrimeField>(Vec<UInt8<ConstraintF>>);

impl<ConstraintF: PrimeField> EqGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(Ok(Boolean::constant(false)), |acc, (a, b)| {
                acc.and_then(|acc| acc.and(&a.is_eq(b)?))
            })
    }
}

impl<ConstraintF: PrimeField> ToBytesGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<ConstraintF: PrimeField> CondSelectGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        assert_eq!(true_value.0.len(), false_value.0.len());

        let bytes: Result<Vec<_>, _> = true_value
            .0
            .iter()
            .zip(false_value.0.iter())
            .map(|(t, f)| UInt8::conditionally_select(cond, t, f))
            .collect();
        Ok(Bytestring(bytes?))
    }
}

impl<ConstraintF: PrimeField> AllocVar<Vec<u8>, ConstraintF> for Bytestring<ConstraintF> {
    // Allocates a vector of UInt8s. This panics if `f()` is `Err`, since we don't know how many
    // bytes to allocate
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f_output = f().expect("cannot allocate a Bytestring of indeterminate length");
        let native_bytes = f_output.borrow();

        let var_bytes: Result<Vec<_>, _> = native_bytes
            .iter()
            .map(|b| UInt8::new_variable(cs.clone(), || Ok(b), mode))
            .collect();

        Ok(Bytestring(var_bytes?))
    }
}

impl<ConstraintF: PrimeField> R1CSVar<ConstraintF> for Bytestring<ConstraintF> {
    type Value = Vec<u8>;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.iter().map(|v| v.value()).collect()
    }
}

// Another helper implementation. This CRH is the identity function in its input
struct IdentityCRHGadget;
impl<ConstraintF: PrimeField> CRHGadget<IdentityCRH, ConstraintF> for IdentityCRHGadget {
    type OutputVar = Bytestring<ConstraintF>;
    type ParametersVar = UnitVar<ConstraintF>;

    fn evaluate(
        _parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        Ok(Bytestring(input.to_vec()))
    }
}

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
    nonce: MC::Randomness,
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
        MC::commit(&self.merkle_com_params, &root_bytes, &self.nonce).map(RootCom)
    }

    /*
    pub fn gen_crs<R, E, P, A, AV, ACG, MCG>(
        rng: &mut R,
        checker: P,
    ) -> Result<TreeProvingKey<E, A, AV, AC, ACG, MC, MCG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine,
        P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
        A: Attrs<AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        ACG: CommitmentGadget<AC, E::Fr>,
        MCG: CommitmentGadget<MC, E::Fr>,
    {
        let prover: PredicateProver<_, _, _, _, _, _, _, MCG> = PredicateProver {
            checker,
            attrs: A::default(),
            merkle_root_com: MC::Output::default(),
            _marker: PhantomData,
        };
        let pk = ark_groth16::generate_random_parameters(prover, rng)?;
        Ok(TreeProvingKey {
            pk,
            _marker: PhantomData,
        })
    }
    */
}

/// A circuit that proves that a commitment to `attrs` appears in the Merkle tree of height `height`
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
