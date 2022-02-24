use core::borrow::Borrow;

use crate::attrs::{Attrs, AttrsVar};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    commitment::{self, constraints::CommitmentGadget, CommitmentScheme},
    crh::{bowe_hopwood, pedersen, TwoToOneCRH, CRH},
};
use ark_ec::PairingEngine;
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar as JubjubVar, EdwardsParameters, EdwardsProjective as Jubjub,
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
    r1cs::{Namespace, SynthesisError},
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

// Convenience types for commitment and two-to-one CRH
pub(crate) type PedersenCom<W> = commitment::pedersen::Commitment<Jubjub, W>;
pub(crate) type PedersenComG<W> =
    commitment::pedersen::constraints::CommGadget<Jubjub, JubjubVar, W>;

pub type Nonce<C> = <C as CommitmentScheme>::Randomness;
pub type NonceVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::RandomnessVar;
pub type Com<C> = <C as CommitmentScheme>::Output;
pub type ComVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::OutputVar;
pub type Param<C> = <C as CommitmentScheme>::Parameters;
pub type ParamVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::ParametersVar;

// Example types //

// Pick a pairing engine and a curve defined over E::Fr
pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;
type FqV = ark_ed_on_bls12_381::constraints::FqVar;
type P = ark_ed_on_bls12_381::EdwardsParameters;

// Pick a two-to-one CRH
pub(crate) type H = bowe_hopwood::CRH<EdwardsParameters, Window9x63>;
pub(crate) type HG = bowe_hopwood::constraints::CRHGadget<P, FqV>;

// Pick a commitment scheme
pub(crate) type BigComScheme = PedersenCom<Window8x128>;
pub(crate) type BigComSchemeG = PedersenComG<Window8x128>;

lazy_static! {
    static ref BIG_COM_PARAM: <BigComScheme as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        BigComScheme::setup(&mut rng).unwrap()
    };
}

const NAME_MAXLEN: usize = 16;

#[derive(Clone, Default)]
pub(crate) struct NameAndBirthYear {
    nonce: Nonce<BigComScheme>,
    first_name: [u8; NAME_MAXLEN],
    birth_year: Fr,
}

#[derive(Clone)]
pub(crate) struct NameAndBirthYearVar {
    nonce: NonceVar<BigComScheme, BigComSchemeG, Fr>,
    first_name: Vec<UInt8<Fr>>,
    pub(crate) birth_year: FpVar<Fr>,
}

impl NameAndBirthYear {
    /// Constructs a new `NameAndBirthYear`, sampling a random nonce for commitment
    pub(crate) fn new<R: Rng>(rng: &mut R, first_name: &[u8], birth_year: u16) -> NameAndBirthYear {
        assert!(first_name.len() <= NAME_MAXLEN);
        let nonce = <BigComScheme as CommitmentScheme>::Randomness::rand(rng);
        let mut name_buf = [0u8; 16];
        name_buf[..first_name.len()].copy_from_slice(first_name);

        NameAndBirthYear {
            nonce,
            first_name: name_buf,
            birth_year: Fr::from(birth_year),
        }
    }
}

impl Attrs<Fr, BigComScheme> for NameAndBirthYear {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.first_name.to_vec();
        self.birth_year.serialize(&mut buf).unwrap();
        buf
    }

    fn get_com_param(&self) -> &Param<BigComScheme> {
        &*BIG_COM_PARAM
    }

    fn get_com_nonce(&self) -> &Nonce<BigComScheme> {
        &self.nonce
    }
}

impl ToBytesGadget<Fr> for NameAndBirthYearVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([self.first_name.to_bytes()?, self.birth_year.to_bytes()?].concat())
    }
}

impl AllocVar<NameAndBirthYear, Fr> for NameAndBirthYearVar {
    // Allocates a vector of UInt8s. This panics if `f()` is `Err`, since we don't know how many
    // bytes to allocate
    fn new_variable<T: Borrow<NameAndBirthYear>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_attr = f();

        // Witness the nonce, first name, and birth year
        let nonce = NonceVar::<BigComScheme, BigComSchemeG, Fr>::new_variable(
            ns!(cs, "nonce"),
            || {
                native_attr
                    .as_ref()
                    .map(|a| &a.borrow().nonce)
                    .map_err(|e| *e)
            },
            mode,
        )?;
        let first_name: Vec<UInt8<Fr>> = (0..NAME_MAXLEN)
            .map(|i| {
                UInt8::new_variable(
                    ns!(cs, "name byte"),
                    || {
                        native_attr
                            .as_ref()
                            .map(|a| a.borrow().first_name[i])
                            .map_err(|e| *e)
                    },
                    mode,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let birth_year = FpVar::<Fr>::new_variable(
            ns!(cs, "birth year"),
            || {
                native_attr
                    .as_ref()
                    .map(|a| a.borrow().birth_year)
                    .map_err(|e| *e)
            },
            mode,
        )?;

        // Return the witnessed values
        Ok(NameAndBirthYearVar {
            nonce,
            first_name,
            birth_year,
        })
    }
}

impl AttrsVar<Fr, NameAndBirthYear, BigComScheme, BigComSchemeG> for NameAndBirthYearVar {
    fn get_com_param(&self) -> Result<ParamVar<BigComScheme, BigComSchemeG, Fr>, SynthesisError> {
        let cs = self.first_name[0].cs().or(self.birth_year.cs());
        ParamVar::<_, BigComSchemeG, _>::new_constant(cs, &*BIG_COM_PARAM)
    }

    fn get_com_nonce(&self) -> Result<NonceVar<BigComScheme, BigComSchemeG, Fr>, SynthesisError> {
        Ok(self.nonce.clone())
    }
}
