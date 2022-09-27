//! Defines traits that describe _attributes_, i.e., the data that credentials are intended to
//! commit to and hide.

use crate::poseidon_utils::ComNonce;

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, bits::ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

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

    /// Gets the parameters for the commitment scheme. In general, attributes shouldn't be holding
    /// the parameters. Rather, this function should return a reference to some global value
    /// somewhere.
    fn get_com_param(&self) -> &AC::Parameters;

    /// Gets the commitment nonce
    fn get_com_nonce(&self) -> &ComNonce;

    // Uses the nonce and commitment parameters to deterministically form a commitment to this
    // attribute set
    fn commit(&self) -> AC::Output {
        let param = self.get_com_param();

        // Generate a nonce of the appropriate type using the given nonce as a seed
        let nonce = {
            let nonce_seed = self.get_com_nonce();
            let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
            AC::Randomness::rand(&mut rng)
        };

        // Commit to the serialized attributes
        AC::commit(param, &self.to_bytes(), &nonce).unwrap()
    }
}

/// This describes the ZK-circuit version of `Attrs`. The only requirement is that it holds a
/// commitment nonce, defines a way to commit to itself, and can be constructed from its
/// corresponding `Attrs` object.
pub trait AttrsVar<ConstraintF, A, AC, ACG>: ToBytesGadget<ConstraintF> + Sized
where
    ConstraintF: PrimeField,
    A: Attrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    /// Returns the constraint system used by this var
    fn cs(&self) -> ConstraintSystemRef<ConstraintF>;

    /// Witnesses the secret attrributes for ZK usage
    fn witness_attrs(
        cs: impl Into<Namespace<ConstraintF>>,
        attrs: &A,
    ) -> Result<Self, SynthesisError>;

    /// Gets the parameters for the commitment scheme. In general, attributes shouldn't be holding
    /// the parameters. Rather, this function should return a reference to some global value
    /// somewhere.
    fn get_com_param(&self) -> Result<ACG::ParametersVar, SynthesisError>;

    /// Gets the commitment nonce. Not a variable, but a native nonce. This is witnessed
    /// automatically.
    fn get_com_nonce(&self) -> &ComNonce;

    // Uses the nonce and commitment parameters to deterministically form a commitment to this
    // attribute set
    fn commit(&self) -> Result<ACG::OutputVar, SynthesisError> {
        let cs = self.cs();
        let com_param = self.get_com_param()?;

        // Generate a nonce of the appropriate type using the given nonce as a seed
        let nonce_var = {
            let nonce_seed = self.get_com_nonce();
            let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
            let nonce = AC::Randomness::rand(&mut rng);
            ACG::RandomnessVar::new_witness(ns!(cs, "nonce_var"), || Ok(nonce))?
        };

        // Commit to the serialized attributes
        ACG::commit(&com_param, &self.to_bytes()?, &nonce_var)
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
    type Id: ToConstraintField<ConstraintF>;
    type Seed: ToConstraintField<ConstraintF>;

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
    type Id: ToConstraintFieldGadget<ConstraintF>;
    type Seed: ToConstraintFieldGadget<ConstraintF>;

    fn get_id(&self) -> Result<Self::Id, SynthesisError>;
    fn get_seed(&self) -> Result<Self::Seed, SynthesisError>;
}
