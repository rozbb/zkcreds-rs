use crate::{
    params::{
        Fr, PassportComScheme, PassportComSchemeG, DATE_LEN, DOB_OFFSET, NAME_LEN, NAME_OFFSET,
        NATIONALITY_OFFSET, PASSPORT_COM_PARAM, STATE_ID_LEN,
    },
    passport_dump::PassportDump,
};

use core::borrow::Borrow;

use sha2::{Digest, Sha256};
use zeronym::{
    attrs::{Attrs, AttrsVar},
    Bytestring, ComNonce, ComNonceVar, ComParam, ComParamVar,
};

use ark_ff::{to_bytes, UniformRand};
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
use ark_std::rand::Rng;

/// Stores a subset of the info found in data groups 1 and 2 of a passport
#[derive(Clone)]
pub struct PersonalInfo {
    nonce: ComNonce<PassportComScheme>,
    pub nationality: [u8; STATE_ID_LEN],
    pub name: [u8; NAME_LEN],
    pub dob: Fr,
    pub biometrics: Vec<u8>,
}

impl Default for PersonalInfo {
    fn default() -> PersonalInfo {
        PersonalInfo {
            nonce: ComNonce::<PassportComScheme>::default(),
            nationality: [0u8; STATE_ID_LEN],
            name: [0u8; NAME_LEN],
            dob: Fr::default(),
            biometrics: Vec::new(),
        }
    }
}

/// Stores a subset of the info found in data groups 1 and 2 of a passport
#[derive(Clone)]
pub(crate) struct PersonalInfoVar {
    nonce: ComNonceVar<PassportComScheme, PassportComSchemeG, Fr>,
    pub(crate) nationality: Bytestring<Fr>,
    pub(crate) name: Bytestring<Fr>,
    pub(crate) dob: FpVar<Fr>,
    pub(crate) biometric_hash: Bytestring<Fr>,
}

/// Converts a date string of the form YYMMDD to a u32 whose base-10 representation is precisely
/// that string.
fn date_to_u32(date: &[u8]) -> u32 {
    assert_eq!(date.len(), DATE_LEN);

    // Converts ASCII numbers to the numbers they represent. E.g., int(b"9") = 9 (mod |Fr|)
    fn int(char: u8) -> u32 {
        (char as u32) - 48
    }

    // Convert the year, month, and day separately. b"YY" becomes YY (mod |Fr|), etc.
    let year = (int(date[0]) * 10) + int(date[1]);
    let month = (int(date[2]) * 10) + int(date[3]);
    let day = (int(date[4]) * 10) + int(date[5]);

    // Now combine the values by shifting and adding
    (year * 10000) + (month * 100) + day
}

impl PersonalInfo {
    /// Constructs a new `PersonalInfo`, sampling a random nonce for commitment
    pub(crate) fn new<R: Rng>(
        rng: &mut R,
        nationality: [u8; STATE_ID_LEN],
        name: [u8; NAME_LEN],
        dob: u32,
        biometrics: Vec<u8>,
    ) -> PersonalInfo {
        let nonce = ComNonce::<PassportComScheme>::rand(rng);

        PersonalInfo {
            nonce,
            nationality,
            name,
            dob: Fr::from(dob),
            biometrics,
        }
    }

    pub fn from_passport<R: Rng>(rng: &mut R, dump: &PassportDump) -> PersonalInfo {
        println!("Creating attrs with info from passport");
        crate::passport_dump::print_mrz_info(dump);

        // Create an empty info struct that we'll fill with data
        let mut info = PersonalInfo {
            nonce: ComNonce::<PassportComScheme>::rand(rng),
            ..Default::default()
        };

        // Extract the nationality, name, and DOB from the DG1 blob. The biometrics are set equal
        // to the entire DG2 blob
        info.nationality
            .copy_from_slice(&dump.dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN]);
        info.name
            .copy_from_slice(&dump.dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN]);
        info.dob = Fr::from(date_to_u32(&dump.dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN]));
        info.biometrics = dump.dg2.clone();

        info
    }
}

impl Attrs<Fr, PassportComScheme> for PersonalInfo {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        let biometric_hash = Sha256::digest(&self.biometrics).to_vec();
        to_bytes![self.nationality, self.name, self.dob, biometric_hash].unwrap()
    }

    fn get_com_param(&self) -> &ComParam<PassportComScheme> {
        &*PASSPORT_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce<PassportComScheme> {
        &self.nonce
    }
}

impl ToBytesGadget<Fr> for PersonalInfoVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([
            self.nationality.0.to_bytes()?,
            self.name.0.to_bytes()?,
            self.dob.to_bytes()?,
            self.biometric_hash.0.to_bytes()?,
        ]
        .concat())
    }
}

impl AllocVar<PersonalInfo, Fr> for PersonalInfoVar {
    // Allocates a vector of UInt8s. This panics if `f()` is `Err`, since we don't know how many
    // bytes to allocate
    fn new_variable<T: Borrow<PersonalInfo>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_attrs = f();

        // Make placeholder content if native_attrs is empty
        let default_info = PersonalInfo::default();

        // Unpack the given attributes
        let PersonalInfo {
            ref nonce,
            ref nationality,
            ref name,
            ref dob,
            ref biometrics,
        } = native_attrs
            .as_ref()
            .map(Borrow::borrow)
            .unwrap_or(&default_info);

        let biometric_hash = Sha256::digest(biometrics).to_vec();

        // Witness the nonce
        let nonce = ComNonceVar::<PassportComScheme, PassportComSchemeG, Fr>::new_variable(
            ns!(cs, "nonce"),
            || Ok(nonce),
            mode,
        )?;

        // Witness all the other variables
        let nationality =
            Bytestring::new_variable(ns!(cs, "nationality"), || Ok(nationality.to_vec()), mode)?;
        let name = Bytestring::new_variable(ns!(cs, "name"), || Ok(name.to_vec()), mode)?;
        let dob = FpVar::<Fr>::new_variable(ns!(cs, "birth year"), || Ok(dob), mode)?;
        let biometric_hash =
            Bytestring::new_variable(ns!(cs, "biometric_hash"), || Ok(biometric_hash), mode)?;

        // Return the witnessed values
        Ok(PersonalInfoVar {
            nonce,
            nationality,
            name,
            dob,
            biometric_hash,
        })
    }
}

impl AttrsVar<Fr, PersonalInfo, PassportComScheme, PassportComSchemeG> for PersonalInfoVar {
    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<PassportComScheme, PassportComSchemeG, Fr>, SynthesisError> {
        let cs = self
            .nationality
            .cs()
            .or(self.name.cs())
            .or(self.dob.cs())
            .or(self.biometric_hash.cs());
        ComParamVar::<_, PassportComSchemeG, _>::new_constant(cs, &*PASSPORT_COM_PARAM)
    }

    fn get_com_nonce(
        &self,
    ) -> Result<ComNonceVar<PassportComScheme, PassportComSchemeG, Fr>, SynthesisError> {
        Ok(self.nonce.clone())
    }
}
