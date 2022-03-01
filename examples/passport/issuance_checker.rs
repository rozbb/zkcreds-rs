use crate::{
    ark_sha256::Sha256Gadget,
    params::{
        Fr, PassportComScheme, PassportComSchemeG, DATE_LEN, DG1_HASH_OFFSET, DG1_LEN,
        DG2_HASH_OFFSET, DOB_OFFSET, DOCUMENT_NUMBER_LEN, DOCUMENT_NUMBER_OFFSET, ECONTENT_LEN,
        EXPIRY_OFFSET, HASH_LEN, ISSUER_OFFSET, NAME_LEN, NAME_OFFSET, NATIONALITY_OFFSET,
        PRE_ECONTENT_HASH_OFFSET, PRE_ECONTENT_LEN, SIG_HASH_LEN, STATE_ID_LEN,
    },
    passport_info::{PassportInfo, PassportInfoVar},
};

use zeronym::{
    attrs::{Attrs, AttrsVar},
    pred::PredicateChecker,
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    ToConstraintFieldGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;

/// Verifies that a given `PassportInfo` hashes to the correct `econtent_hash`
struct IssuanceChecker {
    // Public inputs
    econtent_hash: [u8; SIG_HASH_LEN],

    // Private inputs
    dg1: [u8; DG1_LEN],
    dg2_hash: [u8; HASH_LEN],
    pre_econtent: [u8; PRE_ECONTENT_LEN],
    econtent: [u8; ECONTENT_LEN],
}

/// Converts a date string of the form YYMMDD to a u32 whose base-10 representation is precisely
/// that string.
fn date_to_field_elem(date: &[UInt8<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    assert_eq!(date.len(), DATE_LEN);

    // Converts ASCII numbers to the numbers they represent. E.g., int(b"9") = 9 (mod |Fr|)
    fn int(char: &UInt8<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        let char_fp = Boolean::le_bits_to_fp_var(char.to_bits_le()?.as_slice())?;
        Ok(char_fp - Fr::from(48u16))
    }

    // Constant as field elem
    let ten = Fr::from(10u16);

    // Convert the year, month, and day separately. b"YY" becomes YY (mod |Fr|), etc.
    let year = (int(&date[0])? * ten) + int(&date[1])?;
    let month = (int(&date[2])? * ten) + int(&date[3])?;
    let day = (int(&date[4])? * ten) + int(&date[5])?;

    // Now
    Ok((year * Fr::from(10000u16)) + (month * Fr::from(100u16)) + day)
}

impl PredicateChecker<Fr, PassportInfo, PassportInfoVar, PassportComScheme, PassportComSchemeG>
    for IssuanceChecker
{
    /// Enforces that the given passport info hashes to the given econtent hash. The process of
    /// constructing econtent is complicated, so this is multiple steps
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportInfoVar,
    ) -> Result<(), SynthesisError> {
        // Witness everything
        let dg1 = UInt8::new_witness_vec(ns!(cs, "dg1"), &self.dg1)?;
        let pre_econtent = UInt8::new_witness_vec(ns!(cs, "pre-econtent"), &self.pre_econtent)?;
        let econtent = UInt8::new_witness_vec(ns!(cs, "econtent"), &self.econtent)?;
        let econtent_hash = UInt8::new_input_vec(ns!(cs, "econtent hash"), &self.econtent)?;

        // Check that all the base-level bytestrings match
        dg1[DOCUMENT_NUMBER_OFFSET..DOCUMENT_NUMBER_OFFSET + DOCUMENT_NUMBER_LEN]
            .enforce_equal(&attrs.document_number.0)?;
        dg1[ISSUER_OFFSET..ISSUER_OFFSET + STATE_ID_LEN].enforce_equal(&attrs.issuer.0)?;
        dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN]
            .enforce_equal(&attrs.nationality.0)?;
        dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN].enforce_equal(&attrs.name.0)?;

        // Check the dates match
        date_to_field_elem(&dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN])?.enforce_equal(&attrs.dob)?;
        date_to_field_elem(&dg1[EXPIRY_OFFSET..EXPIRY_OFFSET + DATE_LEN])?
            .enforce_equal(&attrs.expiry_date)?;

        // Check pre-econtent structure
        let dg1_hash = Sha256Gadget::digest(&dg1)?.0;
        let dg2_hash = &attrs.biometric_hash.0;
        pre_econtent[DG1_HASH_OFFSET..DG1_HASH_OFFSET + HASH_LEN].enforce_equal(&dg1_hash)?;
        pre_econtent[DG2_HASH_OFFSET..DG2_HASH_OFFSET + HASH_LEN].enforce_equal(dg2_hash)?;

        // Check the econtent structure
        let pre_econtent_hash = Sha256Gadget::digest(&pre_econtent)?.0;
        econtent[PRE_ECONTENT_HASH_OFFSET..PRE_ECONTENT_HASH_OFFSET + HASH_LEN]
            .enforce_equal(&pre_econtent_hash)?;

        // Check the econtent hash
        econtent_hash.enforce_equal(&Sha256Gadget::digest(&econtent)?.0)?;

        // All done
        Ok(())
    }

    /// The public input is just the econtent hash
    fn public_inputs(&self) -> Vec<Fr> {
        self.econtent_hash.to_field_elements().unwrap()
    }
}
