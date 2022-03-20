use crate::passport::passport_info::{PersonalInfo, PersonalInfoVar};

use zeronym::proof_data_structures::{
    ForestProvingKey as ZeronymForestPk, ForestVerifyingKey as ZeronymForestVk,
    PredProof as ZeronymPredProof, PredProvingKey as ZeronymPredPk,
    PredVerifyingKey as ZeronymPredVk, TreeProvingKey as ZeronymTreePk,
    TreeVerifyingKey as ZeronymTreeVk,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    commitment::CommitmentScheme,
    crh::{bowe_hopwood, pedersen, TwoToOneCRH},
};
use ark_ec::PairingEngine;
use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsParameters};
use ark_std::{
    io::Write,
    rand::{rngs::StdRng, SeedableRng},
};
use lazy_static::lazy_static;

// Our passport info is Data Group 1 (DG1) of the Essential Files (EF) of Logical Data Structure 1
// (LDS1) of an Electronic Machine Readable Travel Document (eMRTD; aka "passport"). The format
// used is TD3 (as opposed to TD1 or TD2).
// The lengths of the fields below are derived from or directly given in ICAO doc 9303, part 10,
// §4.7.1.3, which can be found at https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
pub(crate) const NAME_LEN: usize = 39;
pub(crate) const DATE_LEN: usize = 6;
pub(crate) const STATE_ID_LEN: usize = 3;
pub(crate) const DOCUMENT_NUMBER_LEN: usize = 9;
pub(crate) const DG1_LEN: usize = 93;
pub(crate) const ISSUER_OFFSET: usize = 7;
pub(crate) const NAME_OFFSET: usize = ISSUER_OFFSET + STATE_ID_LEN;
pub(crate) const DOCUMENT_NUMBER_OFFSET: usize = NAME_OFFSET + NAME_LEN;
pub(crate) const NATIONALITY_OFFSET: usize = DOCUMENT_NUMBER_OFFSET + DOCUMENT_NUMBER_LEN + 1;
pub(crate) const DOB_OFFSET: usize = NATIONALITY_OFFSET + STATE_ID_LEN;
pub(crate) const EXPIRY_OFFSET: usize = DOB_OFFSET + DATE_LEN + 2;

// The following values are specific to US passports, or possibly even just my US passport.

// US passports use SHA-256 for their internal hash calculations, and they also use SHA-256 for the
// final signature (RSA-PKCS1v1.5-SHA256)
pub(crate) const HASH_LEN: usize = 32;
pub(crate) const SIG_HASH_LEN: usize = 32;

// These are intermediate values computed in the calculation of a passport's signature
pub(crate) const PRE_ECONTENT_LEN: usize = 180;
pub(crate) const ECONTENT_LEN: usize = 104;
// The location of the DG1 hash inside pre-econtent
pub(crate) const DG1_HASH_OFFSET: usize = 31;
// The location of the DG2 hash inside pre-econtent
pub(crate) const DG2_HASH_OFFSET: usize = 70;
// The location of the pre-econtent hash inside econtent
pub(crate) const PRE_ECONTENT_HASH_OFFSET: usize = 72;

#[derive(Clone)]
pub(crate) struct Window9x128;
impl pedersen::Window for Window9x128 {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 9;
}

#[derive(Clone)]
pub(crate) struct Window9x63;
impl pedersen::Window for Window9x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 9;
}

// Pick a pairing engine and a curve defined over E::Fr
pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;

// Pick a two-to-one CRH
pub(crate) type H = bowe_hopwood::CRH<EdwardsParameters, Window9x63>;
pub(crate) type HG = bowe_hopwood::constraints::CRHGadget<EdwardsParameters, FqVar>;

// Pick a commitment scheme
pub(crate) type PassportComScheme =
    zeronym::compressed_pedersen::Commitment<EdwardsParameters, Window9x128>;
pub(crate) type PassportComSchemeG =
    zeronym::compressed_pedersen::constraints::CommGadget<EdwardsParameters, FqVar, Window9x128>;

pub(crate) type ComTree = zeronym::com_tree::ComTree<Fr, H, PassportComScheme>;
pub(crate) type ComForest = zeronym::com_forest::ComForest<Fr, H, PassportComScheme>;
pub(crate) type ComTreePath = zeronym::com_tree::ComTreePath<Fr, H, PassportComScheme>;
pub(crate) type ComForestRoots = zeronym::com_forest::ComForestRoots<Fr, H>;

/// Type aliases for Groth16 stuff
pub(crate) type PredProvingKey = ZeronymPredPk<
    Bls12_381,
    PersonalInfo,
    PersonalInfoVar,
    PassportComScheme,
    PassportComSchemeG,
    H,
    HG,
>;
pub(crate) type PredVerifyingKey = ZeronymPredVk<
    Bls12_381,
    PersonalInfo,
    PersonalInfoVar,
    PassportComScheme,
    PassportComSchemeG,
    H,
    HG,
>;
pub(crate) type TreeProvingKey =
    ZeronymTreePk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type TreeVerifyingKey =
    ZeronymTreeVk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type ForestProvingKey =
    ZeronymForestPk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type ForestVerifyingKey =
    ZeronymForestVk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type PredProof = ZeronymPredProof<
    Bls12_381,
    PersonalInfo,
    PersonalInfoVar,
    PassportComScheme,
    PassportComSchemeG,
    H,
    HG,
>;

// Set params
lazy_static! {
    pub(crate) static ref PASSPORT_COM_PARAM: <PassportComScheme as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        PassportComScheme::setup(&mut rng).unwrap()
    };
    pub(crate) static ref MERKLE_CRH_PARAM: <H as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <H as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}
