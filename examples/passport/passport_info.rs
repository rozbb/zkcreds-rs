use crate::params::{
    Fr, PassportComScheme, PassportComSchemeG, DOCUMENT_NUMBER_LEN, HASH_LEN, NAME_LEN,
    PASSPORT_COM_PARAM, STATE_ID_LEN,
};

use core::borrow::Borrow;

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
#[derive(Clone, Default)]
pub(crate) struct PassportInfo {
    nonce: ComNonce<PassportComScheme>,
    document_number: [u8; DOCUMENT_NUMBER_LEN],
    issuer: [u8; STATE_ID_LEN],
    nationality: [u8; STATE_ID_LEN],
    name: [u8; NAME_LEN],
    dob: Fr,
    expiry_date: Fr,
    biometric_hash: [u8; HASH_LEN],
}

/// Stores a subset of the info found in data groups 1 and 2 of a passport
#[derive(Clone)]
pub(crate) struct PassportInfoVar {
    nonce: ComNonceVar<PassportComScheme, PassportComSchemeG, Fr>,
    pub(crate) document_number: Bytestring<Fr>,
    pub(crate) issuer: Bytestring<Fr>,
    pub(crate) nationality: Bytestring<Fr>,
    pub(crate) name: Bytestring<Fr>,
    pub(crate) dob: FpVar<Fr>,
    pub(crate) expiry_date: FpVar<Fr>,
    pub(crate) biometric_hash: Bytestring<Fr>,
}

impl PassportInfo {
    /// Constructs a new `PassportInfo`, sampling a random nonce for commitment
    pub(crate) fn new<R: Rng>(
        rng: &mut R,
        document_number: [u8; DOCUMENT_NUMBER_LEN],
        issuer: [u8; STATE_ID_LEN],
        nationality: [u8; STATE_ID_LEN],
        name: [u8; NAME_LEN],
        dob: u32,
        expiry_date: u32,
        biometric_hash: [u8; HASH_LEN],
    ) -> PassportInfo {
        let nonce = ComNonce::<PassportComScheme>::rand(rng);

        PassportInfo {
            nonce,
            document_number,
            issuer,
            nationality,
            name,
            dob: Fr::from(dob),
            expiry_date: Fr::from(expiry_date),
            biometric_hash,
        }
    }
}

impl Attrs<Fr, PassportComScheme> for PassportInfo {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes![
            self.document_number,
            self.issuer,
            self.nationality,
            self.name,
            self.dob,
            self.expiry_date,
            self.biometric_hash
        ]
        .unwrap()
    }

    fn get_com_param(&self) -> &ComParam<PassportComScheme> {
        &*PASSPORT_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce<PassportComScheme> {
        &self.nonce
    }
}

impl ToBytesGadget<Fr> for PassportInfoVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([
            self.document_number.0.to_bytes()?,
            self.issuer.0.to_bytes()?,
            self.nationality.0.to_bytes()?,
            self.name.0.to_bytes()?,
            self.dob.to_bytes()?,
            self.expiry_date.to_bytes()?,
            self.biometric_hash.0.to_bytes()?,
        ]
        .concat())
    }
}

impl AllocVar<PassportInfo, Fr> for PassportInfoVar {
    // Allocates a vector of UInt8s. This panics if `f()` is `Err`, since we don't know how many
    // bytes to allocate
    fn new_variable<T: Borrow<PassportInfo>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_attrs = f();

        // Make placeholder content if native_attrs is empty
        let default_info = PassportInfo::default();

        // Unpack the given attributes
        let PassportInfo {
            ref nonce,
            ref document_number,
            ref issuer,
            ref nationality,
            ref name,
            ref dob,
            ref expiry_date,
            ref biometric_hash,
        } = native_attrs
            .as_ref()
            .map(Borrow::borrow)
            .unwrap_or(&default_info);

        // Witness the nonce
        let nonce = ComNonceVar::<PassportComScheme, PassportComSchemeG, Fr>::new_variable(
            ns!(cs, "nonce"),
            || Ok(nonce),
            mode,
        )?;

        // Witness all the other variables
        let document_number =
            Bytestring::new_variable(ns!(cs, "doc number"), || Ok(document_number.to_vec()), mode)?;
        let issuer = Bytestring::new_variable(ns!(cs, "issuer"), || Ok(issuer.to_vec()), mode)?;
        let nationality =
            Bytestring::new_variable(ns!(cs, "nationality"), || Ok(nationality.to_vec()), mode)?;
        let name = Bytestring::new_variable(ns!(cs, "name"), || Ok(name.to_vec()), mode)?;
        let dob = FpVar::<Fr>::new_variable(ns!(cs, "birth year"), || Ok(dob), mode)?;
        let expiry_date =
            FpVar::<Fr>::new_variable(ns!(cs, "birth year"), || Ok(expiry_date), mode)?;
        let biometric_hash = Bytestring::new_variable(
            ns!(cs, "biometric_hash"),
            || Ok(biometric_hash.to_vec()),
            mode,
        )?;

        // Return the witnessed values
        Ok(PassportInfoVar {
            nonce,
            document_number,
            issuer,
            nationality,
            name,
            dob,
            expiry_date,
            biometric_hash,
        })
    }
}

impl AttrsVar<Fr, PassportInfo, PassportComScheme, PassportComSchemeG> for PassportInfoVar {
    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<PassportComScheme, PassportComSchemeG, Fr>, SynthesisError> {
        let cs = self
            .document_number
            .cs()
            .or(self.issuer.cs())
            .or(self.nationality.cs())
            .or(self.name.cs())
            .or(self.dob.cs())
            .or(self.expiry_date.cs())
            .or(self.biometric_hash.cs());
        ComParamVar::<_, PassportComSchemeG, _>::new_constant(cs, &*PASSPORT_COM_PARAM)
    }

    fn get_com_nonce(
        &self,
    ) -> Result<ComNonceVar<PassportComScheme, PassportComSchemeG, Fr>, SynthesisError> {
        Ok(self.nonce.clone())
    }
}
