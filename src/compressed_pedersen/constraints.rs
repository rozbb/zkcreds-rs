use crate::compressed_pedersen::{Commitment, Parameters, Randomness};

use core::{borrow::Borrow, iter, marker::PhantomData};

use ark_crypto_primitives::{
    commitment::CommitmentGadget as CommitmentGadgetTrait, crh::pedersen::Window,
};
use ark_ec::{ModelParameters, TEModelParameters};
use ark_ff::{
    fields::{Field, PrimeField},
    to_bytes, Zero,
};
use ark_r1cs_std::{groups::curves::twisted_edwards::AffineVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use derivative::Derivative;

type ConstraintF<P> = <<P as ModelParameters>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(Clone(bound = "P: TEModelParameters"))]
pub struct ParametersVar<P: TEModelParameters> {
    params: Parameters<P>,
}

#[derive(Clone, Debug)]
pub struct RandomnessVar<F: Field>(Vec<UInt8<F>>);

pub struct CommGadget<P: TEModelParameters, F: FieldVar<P::BaseField, ConstraintF<P>>, W: Window> {
    #[doc(hidden)]
    _curve: PhantomData<*const P>,
    #[doc(hidden)]
    _field_var: PhantomData<*const F>,
    #[doc(hidden)]
    _window: PhantomData<*const W>,
}

impl<P, F, W> CommitmentGadgetTrait<Commitment<P, W>, ConstraintF<P>> for CommGadget<P, F, W>
where
    P: TEModelParameters,
    F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>
        + TwoBitLookupGadget<<P::BaseField as Field>::BasePrimeField, TableConstant = P::BaseField>
        + ThreeBitCondNegLookupGadget<
            <P::BaseField as Field>::BasePrimeField,
            TableConstant = P::BaseField,
        >,
    W: Window,
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    ConstraintF<P>: PrimeField,
{
    type OutputVar = F;
    type ParametersVar = ParametersVar<P>;
    type RandomnessVar = RandomnessVar<ConstraintF<P>>;

    fn commit(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF<P>>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        assert!((input.len() * 8) <= (W::WINDOW_SIZE * W::NUM_WINDOWS));

        // Convert input bytes to little-endian bits
        let mut input_in_bits: Vec<Boolean<_>> = input
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap())
            .collect();

        // Pad input to `W::WINDOW_SIZE * W::NUM_WINDOWS`.
        let padding_size = (W::WINDOW_SIZE * W::NUM_WINDOWS) - input_in_bits.len();
        input_in_bits.extend(iter::repeat(Boolean::FALSE).take(padding_size));

        // Sanity checks
        assert_eq!(input_in_bits.len(), W::WINDOW_SIZE * W::NUM_WINDOWS);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS);

        // Compute the unblinded commitment. Chunk the input bits into correctly sized windows
        let input_in_bits = input_in_bits.chunks(W::WINDOW_SIZE);
        let mut result = AffineVar::precomputed_base_multiscalar_mul_le(
            &parameters.params.generators,
            input_in_bits,
        )?;

        // Now add in the blinding factor h^r
        let rand_bits: Vec<_> =
            r.0.iter()
                .flat_map(|byte| byte.to_bits_le().unwrap())
                .collect();
        result.precomputed_base_scalar_mul_le(
            rand_bits
                .iter()
                .zip(&parameters.params.randomness_generator),
        )?;

        Ok(result.x)
    }
}

impl<P> AllocVar<Parameters<P>, ConstraintF<P>> for ParametersVar<P>
where
    P: TEModelParameters,
{
    fn new_variable<T: Borrow<Parameters<P>>>(
        _cs: impl Into<Namespace<ConstraintF<P>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(ParametersVar { params })
    }
}

impl<P, F> AllocVar<Randomness<P>, F> for RandomnessVar<F>
where
    P: TEModelParameters,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<P>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f().map(|b| b.borrow().0).unwrap_or(P::ScalarField::zero())].unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

impl<F: PrimeField> R1CSVar<F> for RandomnessVar<F> {
    type Value = F;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        // We don't have the type info to convert our bytes back into a P::ScalarField. P isn't in
        // scope here!
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsParameters, Fq, Fr};
    use ark_std::{test_rng, UniformRand};

    use crate::compressed_pedersen::{constraints::CommGadget, Commitment, Randomness};
    use ark_crypto_primitives::{crh::pedersen, CommitmentGadget, CommitmentScheme};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;

    /// Checks that the primitive Pedersen commitment matches the gadget version
    #[test]
    fn commitment_gadget_test() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        #[derive(Clone, PartialEq, Eq, Hash)]
        pub(super) struct Window;

        impl pedersen::Window for Window {
            const WINDOW_SIZE: usize = 4;
            const NUM_WINDOWS: usize = 9;
        }

        let input = [1u8; 4];

        let rng = &mut test_rng();

        type TestCOMM = Commitment<EdwardsParameters, Window>;
        type TestCOMMGadget = CommGadget<EdwardsParameters, FqVar, Window>;

        let randomness = Randomness(Fr::rand(rng));

        let parameters = Commitment::<EdwardsParameters, Window>::setup(rng).unwrap();
        let primitive_result =
            Commitment::<EdwardsParameters, Window>::commit(&parameters, &input, &randomness)
                .unwrap();

        let mut input_var = vec![];
        for input_byte in input.iter() {
            input_var.push(UInt8::new_witness(cs.clone(), || Ok(*input_byte)).unwrap());
        }

        let randomness_var =
            <TestCOMMGadget as CommitmentGadget<TestCOMM, Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness),
            )
            .unwrap();
        let parameters_var =
            <TestCOMMGadget as CommitmentGadget<TestCOMM, Fq>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "gadget_parameters"),
                || Ok(&parameters),
            )
            .unwrap();
        let result_var =
            TestCOMMGadget::commit(&parameters_var, &input_var, &randomness_var).unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
