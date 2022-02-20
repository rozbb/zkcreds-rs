use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, bits::ToBytesGadget};
use ark_relations::r1cs::SynthesisError;

/// This describes any object which holds attributes. The requirement is that it holds a commitment
/// nonce and defines a way to commit to itself.
pub trait Attrs<AC: CommitmentScheme>: Default {
    fn to_bytes(&self) -> Vec<u8>;

    fn get_com_param(&self) -> &AC::Parameters;

    fn get_com_nonce(&self) -> &AC::Randomness;

    fn commit(&self) -> AC::Output {
        let param = self.get_com_param();
        let nonce = self.get_com_nonce();
        AC::commit(param, &self.to_bytes(), nonce).unwrap()
    }
}

/// This describes the ZK-circuit version of `Attrs`. The only requirement is that it holds a
/// commitment nonce, defines a way to commit to itself, and can be constructed from its
/// corresponding `Attrs` object.
pub trait AttrsVar<ConstraintF, A, AC, ACG>:
    AllocVar<A, ConstraintF> + ToBytesGadget<ConstraintF>
where
    ConstraintF: PrimeField,
    A: Attrs<AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    fn get_com_param(&self) -> Result<ACG::ParametersVar, SynthesisError>;

    fn get_com_nonce(&self) -> Result<ACG::RandomnessVar, SynthesisError>;

    fn commit(&self) -> Result<ACG::OutputVar, SynthesisError> {
        let com_param = self.get_com_param()?;
        let nonce = self.get_com_nonce()?;
        ACG::commit(&com_param, &self.to_bytes()?, &nonce)
    }
}
