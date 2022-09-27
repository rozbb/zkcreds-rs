//! Defines some structs for testing purposes

use core::borrow::Borrow;

use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar, Attrs, AttrsVar},
    poseidon_utils::{Bls12PoseidonCommitter, ComNonce},
    pred::PredicateChecker,
    zk_utils::UnitVar,
    Bytestring, Com, ComNonceVar, ComParam, ComParamVar,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    commitment::{self, constraints::CommitmentGadget, CommitmentScheme},
    crh::{bowe_hopwood, pedersen, TwoToOneCRH, CRH},
};
use ark_ec::PairingEngine;
use ark_ed_on_bls12_381::{
    constraints::{EdwardsVar as JubjubVar, FqVar},
    EdwardsParameters, EdwardsProjective as Jubjub,
};
use ark_ff::UniformRand;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    io::Write,
    rand::{rngs::StdRng, Rng, SeedableRng},
};
use lazy_static::lazy_static;

// Define different window sizes for Pedersen commitments

#[derive(Clone)]
pub struct Window8x63;
impl pedersen::Window for Window8x63 {
    const WINDOW_SIZE: usize = 63;
    // This can be made smaller than 8, but the program panics if it's not divisible by 8. Tracking
    // issue here: https://github.com/arkworks-rs/crypto-primitives/issues/76
    const NUM_WINDOWS: usize = 8;
}

#[derive(Clone)]
pub struct Window8x128;
impl pedersen::Window for Window8x128 {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 8;
}

#[derive(Clone)]
pub struct Window3x63;
impl pedersen::Window for Window3x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 3;
}

#[derive(Clone)]
pub struct Window9x63;
impl pedersen::Window for Window9x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 9;
}

#[derive(Clone)]
pub struct Window17x63;
impl pedersen::Window for Window17x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 17;
}

// Convenience types for commitment and two-to-one CRH
pub(crate) type PedersenCom<W> = commitment::pedersen::Commitment<Jubjub, W>;
pub(crate) type PedersenComG<W> =
    commitment::pedersen::constraints::CommGadget<Jubjub, JubjubVar, W>;

pub(crate) type CompressedPedersenCom<W> =
    crate::compressed_pedersen::Commitment<EdwardsParameters, W>;
pub(crate) type CompressedPedersenComG<W> =
    crate::compressed_pedersen::constraints::CommGadget<EdwardsParameters, FqVar, W>;

// Example types //

// Pick a pairing engine and a curve defined over E::Fr
pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;

// Pick a two-to-one CRH
pub type TestTreeH = bowe_hopwood::CRH<EdwardsParameters, Window9x63>;
pub type TestTreeHG = bowe_hopwood::constraints::CRHGadget<EdwardsParameters, FqVar>;

// Pick a commitment scheme
pub type TestComSchemePedersen = CompressedPedersenCom<Window8x128>;
pub type TestComSchemePedersenG = CompressedPedersenComG<Window8x128>;
//pub(crate) type TestComScheme = PedersenCom<Window8x128>;
//pub(crate) type TestComSchemeG = PedersenComG<Window8x128>;

lazy_static! {
    static ref BIG_COM_PARAM: <TestComSchemePedersen as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        TestComSchemePedersen::setup(&mut rng).unwrap()
    };
    pub static ref MERKLE_CRH_PARAM: <TestTreeH as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <TestTreeH as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}

const NAME_MAXLEN: usize = 16;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameAndBirthYear {
    nonce: ComNonce,
    seed: Fr,
    first_name: [u8; NAME_MAXLEN],
    birth_year: Fr,
}

#[derive(Clone)]
pub struct NameAndBirthYearVar {
    nonce: ComNonce,
    seed: FpVar<Fr>,
    first_name: Vec<UInt8<Fr>>,
    pub(crate) birth_year: FpVar<Fr>,
}

impl NameAndBirthYear {
    /// Constructs a new `NameAndBirthYear`, sampling a random nonce for commitment
    pub fn new<R: Rng>(rng: &mut R, first_name: &[u8], birth_year: u16) -> NameAndBirthYear {
        assert!(first_name.len() <= NAME_MAXLEN);
        let mut name_buf = [0u8; 16];
        name_buf[..first_name.len()].copy_from_slice(first_name);

        let nonce = ComNonce::rand(rng);
        let seed = Fr::rand(rng);

        NameAndBirthYear {
            nonce,
            seed,
            first_name: name_buf,
            birth_year: Fr::from(birth_year),
        }
    }
}

impl Attrs<Fr, TestComSchemePedersen> for NameAndBirthYear {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.first_name.to_vec();
        self.birth_year.serialize(&mut buf).unwrap();
        buf
    }

    fn get_com_param(&self) -> &ComParam<TestComSchemePedersen> {
        &*BIG_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl Attrs<Fr, Bls12PoseidonCommitter> for NameAndBirthYear {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.first_name.to_vec();
        self.birth_year.serialize(&mut buf).unwrap();
        buf
    }

    fn get_com_param(&self) -> &() {
        &()
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, TestComSchemePedersen> for NameAndBirthYear {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        self.first_name.to_vec()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for NameAndBirthYearVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([self.first_name.to_bytes()?, self.birth_year.to_bytes()?].concat())
    }
}

impl AttrsVar<Fr, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG>
    for NameAndBirthYearVar
{
    /// Returns the constraint system used by this var
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.first_name.cs())
            .or(self.birth_year.cs())
    }

    // Allocates a vector of UInt8s. This panics if `f()` is `Err`, since we don't know how many
    // bytes to allocate
    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        native_attr: &NameAndBirthYear,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();

        // Get the nonce normally. This is not a variable
        let nonce: ComNonce = native_attr.nonce.clone();

        // Witness the seed, first name, and birth year
        let seed = FpVar::new_witness(ns!(cs, "seed"), || Ok(native_attr.seed))?;
        let first_name = UInt8::new_witness_vec(ns!(cs, "first name"), &native_attr.first_name)?;
        let birth_year =
            FpVar::<Fr>::new_witness(ns!(cs, "birth year"), || Ok(native_attr.birth_year))?;

        // Return the witnessed values
        Ok(NameAndBirthYearVar {
            nonce,
            seed,
            first_name,
            birth_year,
        })
    }

    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<TestComSchemePedersen, TestComSchemePedersenG, Fr>, SynthesisError>
    {
        let cs = self.first_name[0].cs().or(self.birth_year.cs());
        ComParamVar::<_, TestComSchemePedersenG, _>::new_constant(cs, &*BIG_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG>
    for NameAndBirthYearVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(Bytestring(self.first_name.clone()))
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}

impl AttrsVar<Fr, NameAndBirthYear, Bls12PoseidonCommitter, Bls12PoseidonCommitter>
    for NameAndBirthYearVar
{
    /// Returns the constraint system used by this var
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.first_name.cs())
            .or(self.birth_year.cs())
    }

    // Allocates a vector of UInt8s. This panics if `f()` is `Err`, since we don't know how many
    // bytes to allocate
    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        native_attr: &NameAndBirthYear,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();

        // Get the nonce normally. This is not a variable
        let nonce: ComNonce = native_attr.nonce.clone();

        // Witness the seed, first name, and birth year
        let seed = FpVar::new_witness(ns!(cs, "seed"), || Ok(native_attr.seed))?;
        let first_name = UInt8::new_witness_vec(ns!(cs, "first name"), &native_attr.first_name)?;
        let birth_year =
            FpVar::<Fr>::new_witness(ns!(cs, "birth year"), || Ok(native_attr.birth_year))?;

        // Return the witnessed values
        Ok(NameAndBirthYearVar {
            nonce,
            seed,
            first_name,
            birth_year,
        })
    }

    fn get_com_param(&self) -> Result<UnitVar<Fr>, SynthesisError> {
        Ok(UnitVar::default())
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, Bls12PoseidonCommitter> for NameAndBirthYear {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        self.first_name.to_vec()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl AccountableAttrsVar<Fr, NameAndBirthYear, Bls12PoseidonCommitter, Bls12PoseidonCommitter>
    for NameAndBirthYearVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(Bytestring(self.first_name.clone()))
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}

// Define a predicate that will tell whether the given `NameAndBirthYear` is at least X years
// old. The predicate is: attrs.birth_year ≤ self.threshold_birth_year
#[derive(Clone)]
pub struct AgeChecker {
    pub threshold_birth_year: Fr,
}

impl
    PredicateChecker<
        Fr,
        NameAndBirthYear,
        NameAndBirthYearVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for AgeChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &NameAndBirthYearVar,
    ) -> Result<(), SynthesisError> {
        // Witness the threshold year as a public input
        let threshold_birth_year =
            FpVar::<Fr>::new_input(ns!(cs, "threshold year"), || Ok(self.threshold_birth_year))?;
        // Assert that attrs.birth_year ≤ threshold_birth_year
        attrs
            .birth_year
            .enforce_cmp(&threshold_birth_year, core::cmp::Ordering::Less, true)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_birth_year]
    }
}

impl
    PredicateChecker<
        Fr,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
    > for AgeChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &NameAndBirthYearVar,
    ) -> Result<(), SynthesisError> {
        // Witness the threshold year as a public input
        let threshold_birth_year =
            FpVar::<Fr>::new_input(ns!(cs, "threshold year"), || Ok(self.threshold_birth_year))?;
        // Assert that attrs.birth_year ≤ threshold_birth_year
        attrs
            .birth_year
            .enforce_cmp(&threshold_birth_year, core::cmp::Ordering::Less, true)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_birth_year]
    }
}
