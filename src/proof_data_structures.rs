//! Defines proving and verifying keys for predicates, tree membership, and forest membership

use crate::attrs::{Attrs, AttrsVar};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
};
use ark_ec::PairingEngine;
use ark_ff::ToConstraintField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use linkg16::groth16::{
    Proof as Groth16Proof, ProvingKey as Groth16ProvingKey, VerifyingKey as Groth16VerifyingKey,
};

//
// Predicate data structures
//

/// Represents the proving key for a predicate proof
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PredProvingKey<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) pk: Groth16ProvingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, H, HG)>,
}

impl<E, A, AV, AC, ACG, H, HG> PredProvingKey<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub fn prepare_verifying_key(&self) -> PredVerifyingKey<E, A, AV, AC, ACG, H, HG> {
        let vk = self.pk.verifying_key();
        PredVerifyingKey {
            vk,
            _marker: self._marker,
        }
    }
}

impl<E, A, AV, AC, ACG, H, HG> Clone for PredProvingKey<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            _marker: PhantomData,
        }
    }
}

/// Represents the verifying key for a predicate proofs
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PredVerifyingKey<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) vk: Groth16VerifyingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, H, HG)>,
}

impl<E, A, AV, AC, ACG, H, HG> Clone for PredVerifyingKey<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            vk: self.vk.clone(),
            _marker: PhantomData,
        }
    }
}

/// Represents the prepared public inputs to a predicate proof
pub struct PredPublicInput<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) pinput: E::G1Projective,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, H, HG)>,
}

/// Represents a predicate proof
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PredProof<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) proof: Groth16Proof<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG, H, HG)>,
}

impl<E, A, AV, AC, ACG, H, HG> Clone for PredProof<E, A, AV, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        PredProof {
            proof: self.proof.clone(),
            _marker: PhantomData,
        }
    }
}

//
// Birth predicate data structures
//

/// Represents the proving key for a predicate proof
pub struct BirthProvingKey<E, A, AV, AC, ACG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
{
    pub(crate) pk: Groth16ProvingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG)>,
}

impl<E, A, AV, AC, ACG> BirthProvingKey<E, A, AV, AC, ACG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
{
    pub fn prepare_verifying_key(&self) -> BirthVerifyingKey<E, A, AV, AC, ACG> {
        let vk = self.pk.verifying_key();
        BirthVerifyingKey {
            vk,
            _marker: self._marker,
        }
    }
}

/// Represents the verifying key for a predicate proofs
pub struct BirthVerifyingKey<E, A, AV, AC, ACG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
{
    pub(crate) vk: Groth16VerifyingKey<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG)>,
}

/// Represents the prepared public inputs to a predicate proof
pub struct BirthPublicInput<E, A, AV, AC, ACG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
{
    pub(crate) pinput: E::G1Projective,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG)>,
}

/// Represents a predicate proof
pub struct BirthProof<E, A, AV, AC, ACG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
{
    pub(crate) proof: Groth16Proof<E>,
    pub(crate) _marker: PhantomData<(A, AV, AC, ACG)>,
}

//
// Merkle tree membership data structures
//

/// Represents the proving key for a Merkle tree membership proof
pub struct TreeProvingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) pk: Groth16ProvingKey<E>,
    pub(crate) _marker: PhantomData<(A, AC, ACG, H, HG)>,
}

impl<E, A, AC, ACG, H, HG> Clone for TreeProvingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, A, AC, ACG, H, HG> TreeProvingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub fn prepare_verifying_key(&self) -> TreeVerifyingKey<E, A, AC, ACG, H, HG> {
        let vk = self.pk.verifying_key();
        TreeVerifyingKey {
            vk,
            _marker: self._marker,
        }
    }
}

/// Represents the verifying key for Merkle tree membership proofs
pub struct TreeVerifyingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) vk: Groth16VerifyingKey<E>,
    pub(crate) _marker: PhantomData<(A, AC, ACG, H, HG)>,
}

impl<E, A, AC, ACG, H, HG> Clone for TreeVerifyingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            vk: self.vk.clone(),
            _marker: PhantomData,
        }
    }
}

/// Represents the prepared public inputs to a Merkle tree membership proof
pub struct TreePublicInput<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) pinput: E::G1Projective,
    pub(crate) _marker: PhantomData<(A, AC, ACG, H, HG)>,
}

/// Represents a Merkle tree membership proof
pub struct TreeProof<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) proof: Groth16Proof<E>,
    pub(crate) _marker: PhantomData<(A, AC, ACG, H, HG)>,
}

impl<E, A, AC, ACG, H, HG> Clone for TreeProof<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        TreeProof {
            proof: self.proof.clone(),
            _marker: PhantomData,
        }
    }
}

//
// Merkle forest membership data structures
//

/// Represents the proving key for a Merkle forest membership proof
pub struct ForestProvingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) pk: Groth16ProvingKey<E>,
    pub(crate) _marker: PhantomData<(A, AC, ACG, H, HG)>,
}

impl<E, A, AC, ACG, H, HG> Clone for ForestProvingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, A, AC, ACG, H, HG> ForestProvingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub fn prepare_verifying_key(&self) -> ForestVerifyingKey<E, A, AC, ACG, H, HG> {
        let vk = self.pk.verifying_key();
        ForestVerifyingKey {
            vk,
            _marker: self._marker,
        }
    }
}

/// Represents the verifying key for Merkle forest membership proofs
pub struct ForestVerifyingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) vk: Groth16VerifyingKey<E>,
    pub(crate) _marker: PhantomData<(A, AC, ACG, H, HG)>,
}

impl<E, A, AC, ACG, H, HG> Clone for ForestVerifyingKey<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            vk: self.vk.clone(),
            _marker: PhantomData,
        }
    }
}

/// Represents a Merkle forest membership proof
pub struct ForestProof<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    pub(crate) proof: Groth16Proof<E>,
    pub(crate) _marker: PhantomData<(A, AC, ACG, H, HG)>,
}

impl<E, A, AC, ACG, H, HG> Clone for ForestProof<E, A, AC, ACG, H, HG>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    fn clone(&self) -> Self {
        ForestProof {
            proof: self.proof.clone(),
            _marker: PhantomData,
        }
    }
}
