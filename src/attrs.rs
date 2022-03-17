use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ff::{PrimeField, ToBytes, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, bits::ToBytesGadget};
use ark_relations::r1cs::SynthesisError;

/// This describes any object which holds attributes. The requirement is that it holds a commitment
/// nonce and defines a way to commit to itself.
pub trait Attrs<ConstraintF, AC>: Default
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Serializes EVERYTHING BUT the nonce and param
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
    A: Attrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
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

/// An `Attrs` trait that has something that identifies the user as well as  a random seed we can
/// use for rate limiting
pub trait AccountableAttrs<ConstraintF, AC>: Attrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    type Id: ToBytes;
    type Seed: ToBytes;

    fn get_id(&self) -> Self::Id;
    fn get_seed(&self) -> Self::Seed;
}

/// The gadget version of `AccountableAttrs`
pub trait AccountableAttrsVar<ConstraintF, A, AC, ACG>: AttrsVar<ConstraintF, A, AC, ACG>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    type Id: ToBytesGadget<ConstraintF>;
    type Seed: ToBytesGadget<ConstraintF>;

    fn get_id(&self) -> Result<Self::Id, SynthesisError>;
    fn get_seed(&self) -> Result<Self::Seed, SynthesisError>;
}
