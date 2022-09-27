//! Defines some structs and functions for commitments and hashes based on the Poseidon hash
//! function.

use crate::zk_utils::UnitVar;

use core::fmt;

use ark_bls12_381::Fr as BlsFr;
use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    Error as ArkError,
};
use ark_ff::{to_bytes, PrimeField, ToConstraintField, UniformRand};
use ark_r1cs_std::{
    bits::{uint8::UInt8, ToBytesGadget},
    fields::fp::FpVar,
    R1CSVar, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use arkworks_native_gadgets::poseidon::{
    sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters,
};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};
use arkworks_utils::{bytes_matrix_to_f, bytes_vec_to_f, Curve};
use lazy_static::lazy_static;
use rand::Rng;

/// A commitment nonce is always just a 256 bit value
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ComNonce(pub [u8; 32]);

impl fmt::Debug for ComNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("[omitted]")
    }
}

impl UniformRand for ComNonce {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        ComNonce(UniformRand::rand(rng))
    }
}

impl ComNonce {
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn setup_poseidon_params<F: PrimeField>(
    curve: Curve,
    exp: i8,
    width: u8,
) -> PoseidonParameters<F> {
    let pos_data =
        arkworks_utils::poseidon_params::setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    PoseidonParameters {
        mds_matrix: mds_f,
        round_keys: rounds_f,
        full_rounds: pos_data.full_rounds,
        partial_rounds: pos_data.partial_rounds,
        sbox: PoseidonSbox(pos_data.exp),
        width: pos_data.width,
    }
}

// Pick global parameters for Poseidon over BLS12-381
const POSEIDON_WIDTH: u8 = 5;
const COM_DOMAIN_SEP: &[u8] = b"pcom";
const CRH_DOMAIN_SEP: &[u8] = b"pcrh";
lazy_static! {
    static ref BLS12_POSEIDON_PARAMS: PoseidonParameters<BlsFr> =
        setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
}

/// A commitment scheme defined using the Poseidon hash function over BLS12-381
pub struct Bls12PoseidonCommitter;

fn poseidon_iterated_hash(input: &[BlsFr]) -> BlsFr {
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
    let first_block_len = core::cmp::min(input.len(), (POSEIDON_WIDTH - 1) as usize);

    let first_block = &input[..first_block_len];
    let mut running_hash = hasher.hash(first_block).unwrap();
    for block in input[first_block_len..].chunks((POSEIDON_WIDTH - 2) as usize) {
        let next_input = &[&[running_hash], block].concat();
        running_hash = hasher.hash(next_input).unwrap();
    }
    running_hash
}

fn poseidon_iterated_hash_gadget(
    cs: &mut ConstraintSystemRef<BlsFr>,
    input: &[FpVar<BlsFr>],
) -> Result<FpVar<BlsFr>, SynthesisError> {
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
    let hasher_var = PoseidonGadget::from_native(cs, hasher)?;
    let first_block_len = core::cmp::min(input.len(), (POSEIDON_WIDTH - 1) as usize);

    let first_block = &input[..first_block_len];
    let mut running_hash = hasher_var.hash(first_block)?;
    for block in input[first_block_len..].chunks((POSEIDON_WIDTH - 2) as usize) {
        let next_input = &[&[running_hash], block].concat();
        running_hash = hasher_var.hash(next_input)?;
    }

    Ok(running_hash)
}

impl CommitmentScheme for Bls12PoseidonCommitter {
    type Output = BlsFr;
    // We don't need parameters because they're set globally in the above lazy_static
    type Parameters = ();
    type Randomness = BlsFr;

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ArkError> {
        Ok(())
    }

    // Computes H(domain_sep || randomness || input)
    fn commit(
        _parameters: &Self::Parameters,
        input: &[u8],
        r: &Self::Randomness,
    ) -> Result<Self::Output, ArkError> {
        // Concat all the inputs and pack them into field elements
        let hash_input: Vec<u8> = [COM_DOMAIN_SEP, &to_bytes!(r).unwrap(), input].concat();
        let packed_input: Vec<BlsFr> = hash_input
            .to_field_elements()
            .expect("could not pack inputs");

        // Compute the hash
        Ok(poseidon_iterated_hash(&packed_input))
    }
}

impl CommitmentGadget<Bls12PoseidonCommitter, BlsFr> for Bls12PoseidonCommitter {
    type OutputVar = FpVar<BlsFr>;
    type ParametersVar = UnitVar<BlsFr>;
    type RandomnessVar = FpVar<BlsFr>;

    // Computes H(domain_sep || randomness || input)
    fn commit(
        _parameters: &Self::ParametersVar,
        input: &[UInt8<BlsFr>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut cs = input.cs();

        // Concat all the inputs and pack them into field elements
        let hash_input: Vec<UInt8<BlsFr>> = [
            &UInt8::constant_vec(COM_DOMAIN_SEP),
            &r.to_bytes().unwrap(),
            input,
        ]
        .concat();
        let packed_input: Vec<FpVar<BlsFr>> = hash_input
            .to_constraint_field()
            .expect("could not pack inputs");

        // Compute the hash
        poseidon_iterated_hash_gadget(&mut cs, &packed_input)
    }
}

/// Represents the collision-resistant hashing functionality of Poseidon over BLS12-381
pub struct Bls12PoseidonCrh;

// TODO: Once arkworks-native-gadgets updates to the new Arkworks version, update this to use the
// new Arkworks trait TwoToOneCRHScheme
// https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-native-gadgets/src/mimc.rs#L2=
use ark_crypto_primitives::crh::{TwoToOneCRH, TwoToOneCRHGadget};

impl TwoToOneCRH for Bls12PoseidonCrh {
    // This doesn't matter. We only use it for Merkle tree stuff
    const LEFT_INPUT_SIZE_BITS: usize = 0;
    const RIGHT_INPUT_SIZE_BITS: usize = 0;

    type Parameters = ();
    type Output = BlsFr;

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ArkError> {
        Ok(())
    }

    // Evaluates H(left || right)
    fn evaluate(_: &(), left_input: &[u8], right_input: &[u8]) -> Result<BlsFr, ArkError> {
        // We only use this for Merkle tree hashing over BLS12-381, so just fix the input len to 32
        assert_eq!(left_input.len(), 32);
        assert_eq!(right_input.len(), 32);

        // Concat all the inputs and pack them into field elements
        let hash_input: Vec<u8> = [CRH_DOMAIN_SEP, left_input, right_input].concat();
        let packed_input: Vec<BlsFr> = hash_input
            .to_field_elements()
            .expect("could not pack inputs");

        // Compute the hash
        Ok(poseidon_iterated_hash(&packed_input))
    }
}

// Do the same thing for ZK land
impl TwoToOneCRHGadget<Bls12PoseidonCrh, BlsFr> for Bls12PoseidonCrh {
    type ParametersVar = UnitVar<BlsFr>;
    type OutputVar = FpVar<BlsFr>;

    // Evaluates H(left || right)
    fn evaluate(
        _: &UnitVar<BlsFr>,
        left_input: &[UInt8<BlsFr>],
        right_input: &[UInt8<BlsFr>],
    ) -> Result<FpVar<BlsFr>, SynthesisError> {
        // We only use this for Merkle tree hashing over BLS12-381, so just fix the input len to 32
        assert_eq!(left_input.len(), 32);
        assert_eq!(right_input.len(), 32);

        let mut cs = left_input.cs().or(right_input.cs());

        // Concat all the inputs and pack them into field elements
        let hash_input: Vec<UInt8<_>> = [
            &UInt8::constant_vec(CRH_DOMAIN_SEP),
            left_input,
            right_input,
        ]
        .concat();
        let packed_input: Vec<FpVar<BlsFr>> = hash_input
            .to_constraint_field()
            .expect("could not pack inputs");

        // Compute the hash
        poseidon_iterated_hash_gadget(&mut cs, &packed_input)
    }
}
