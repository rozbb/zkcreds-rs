use crate::attrs::{Attrs, AttrsVar};

use core::marker::PhantomData;

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ec::PairingEngine;
use ark_groth16::{
    PreparedVerifyingKey as Groth16PreparedVerifyingKey, Proof as Groth16Proof,
    ProvingKey as Groth16ProvingKey,
};

//
// Predicate data structures
//

/// Represents the proving key for a predicate proof
pub struct PredProvingKey<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) pk: Groth16ProvingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}

/// Represents the verifying key for a predicate proofs
pub struct PredVerifyingKey<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) pvk: Groth16PreparedVerifyingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}

/// Represents the prepared public inputs to a predicate proof
pub struct PredPublicInput<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) pinput: E::G1Projective,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}

/// Represents a predicate proof
pub struct PredProof<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) proof: Groth16Proof<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}

//
// Merkle tree membership data structures
//

/// Represents the proving key for a Merkle tree membership proof
pub struct TreeProvingKey<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) pk: Groth16ProvingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}

/// Represents the verifying key for Merkle tree membership proofs
pub struct TreeVerifyingKey<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) pvk: Groth16PreparedVerifyingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}

/// Represents the prepared public inputs to a Merkle tree membership proof
pub struct TreePublicInput<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) pinput: E::G1Projective,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}

/// Represents a Merkle tree membership proof
pub struct TreeProof<E, A, AV, AC, ACG, MC, MCG>
where
    E: PairingEngine,
    A: Attrs<AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    MC: CommitmentScheme,
    MCG: CommitmentGadget<MC, E::Fr>,
{
    pub(crate) proof: Groth16Proof<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, MC, MCG)>,
}
