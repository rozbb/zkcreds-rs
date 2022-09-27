//! Some helpful utilities for making zero-knowledge circuits in arkworks

use core::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{constraints::CRHGadget, CRH},
    Error as ArkError,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar, ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::rand::Rng;

/// This CRH is the identity function on its input
pub struct IdentityCRH;
impl CRH for IdentityCRH {
    /// This value doesn't matter. We return everything no matter what
    const INPUT_SIZE_BITS: usize = 0;

    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, ArkError> {
        Ok(())
    }

    /// Returns the input
    fn evaluate(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, ArkError> {
        Ok(input.to_vec())
    }
}

/// This CRH is the identity function in its input
pub struct IdentityCRHGadget;
impl<ConstraintF: PrimeField> CRHGadget<IdentityCRH, ConstraintF> for IdentityCRHGadget {
    /// A `Bytestring` is just a wrapper around `Vec<UInt8<F>>`
    type OutputVar = Bytestring<ConstraintF>;

    /// A `UnitVar` is literally the unit type, in variable form
    type ParametersVar = UnitVar<ConstraintF>;

    /// Returns the input
    fn evaluate(
        _parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        Ok(Bytestring(input.to_vec()))
    }
}

/// The unit type for circuit variables. This contains no data.
#[derive(Clone, Debug, Default)]
pub struct UnitVar<ConstraintF: PrimeField>(PhantomData<ConstraintF>);

impl<ConstraintF: PrimeField> AllocVar<(), ConstraintF> for UnitVar<ConstraintF> {
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(UnitVar(PhantomData))
    }
}

/// This type is the output of the `IdentityCRH`. It's just a `Vec<UInt8<F>>`. The reason we have
/// to make a newtype is because `Vec<UInt8<F>>` doesn't implement `EqGadget` or `AllocVar`.
#[derive(Clone, Debug)]
pub struct Bytestring<ConstraintF: PrimeField>(pub Vec<UInt8<ConstraintF>>);

// Implement all the necessary traits below

impl<ConstraintF: PrimeField> EqGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.0.as_slice().is_eq(other.0.as_slice())
    }
}

impl<ConstraintF: PrimeField> ToBytesGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<ConstraintF: PrimeField> ToConstraintFieldGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<ConstraintF>>, SynthesisError> {
        self.0.to_constraint_field()
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
        bytes.map(Bytestring)
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

        var_bytes.map(Bytestring)
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
