use crate::{
    ark_sha256::Sha256Gadget,
    params::{
        Fr, PassportComScheme, PassportComSchemeG, DATE_LEN, DG1_HASH_OFFSET, DG1_LEN,
        DG2_HASH_OFFSET, DOB_OFFSET, ECONTENT_LEN, EXPIRY_OFFSET, HASH_LEN, ISSUER_OFFSET,
        NAME_LEN, NAME_OFFSET, NATIONALITY_OFFSET, PRE_ECONTENT_HASH_OFFSET, PRE_ECONTENT_LEN,
        SIG_HASH_LEN, STATE_ID_LEN,
    },
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
};

use zeronym::pred::PredicateChecker;

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use sha2::{Digest, Sha256};

/// Verifies that the `PassportDump` hashes to the correct `econtent_hash`, and that the
/// `PersonalAttrs` corresponds to its contents.
#[derive(Clone)]
pub struct IssuanceChecker {
    // Public inputs
    econtent_hash: [u8; SIG_HASH_LEN],
    expected_issuer: [u8; STATE_ID_LEN],
    today: Fr,

    // Private inputs
    dg1: [u8; DG1_LEN],
    pre_econtent: [u8; PRE_ECONTENT_LEN],
    econtent: [u8; ECONTENT_LEN],
}

impl IssuanceChecker {
    /// Makes an issuance checker given a passport, 3-letter issuing state, and DOB in the form
    /// YYMMDD in base-10
    pub fn from_passport(
        dump: &PassportDump,
        expected_issuer: [u8; STATE_ID_LEN],
        today: u32,
    ) -> IssuanceChecker {
        let mut dg1 = [0u8; DG1_LEN];
        let mut pre_econtent = [0u8; PRE_ECONTENT_LEN];
        let mut econtent = [0u8; ECONTENT_LEN];
        let mut econtent_hash = [0u8; SIG_HASH_LEN];

        dg1.copy_from_slice(&dump.dg1);
        pre_econtent.copy_from_slice(&dump.pre_econtent);
        econtent.copy_from_slice(&dump.econtent);
        econtent_hash.copy_from_slice(&Sha256::digest(econtent));

        IssuanceChecker {
            econtent_hash,
            expected_issuer,
            today: Fr::from(today),
            dg1,
            pre_econtent,
            econtent,
        }
    }
}

/// Converts a date string of the form YYMMDD to a field element whose canonical base-10
/// representation is precisely that string.
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

    // Now combine the values by shifting and adding
    let f = (year * Fr::from(10000u16)) + (month * Fr::from(100u16)) + day;
    Ok(f)
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for IssuanceChecker
{
    /// Enforces that the given passport info hashes to the given econtent hash. The process of
    /// constructing econtent is complicated, so this is multiple steps
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // Witness public inputs
        let econtent_hash = UInt8::new_input_vec(ns!(cs, "econtent hash"), &self.econtent_hash)?;
        let expected_issuer =
            UInt8::new_input_vec(ns!(cs, "expected issuer"), &self.expected_issuer)?;
        let today = FpVar::<Fr>::new_input(ns!(cs, "expiry threshold"), || Ok(self.today))?;

        // Witness private inputs
        let dg1 = UInt8::new_witness_vec(ns!(cs, "dg1"), &self.dg1)?;
        let pre_econtent = UInt8::new_witness_vec(ns!(cs, "pre-econtent"), &self.pre_econtent)?;
        let econtent = UInt8::new_witness_vec(ns!(cs, "econtent"), &self.econtent)?;

        // Check that the issuer is the expected one, and the passport isn't expired
        dg1[ISSUER_OFFSET..ISSUER_OFFSET + STATE_ID_LEN].enforce_equal(&expected_issuer)?;
        date_to_field_elem(&dg1[EXPIRY_OFFSET..EXPIRY_OFFSET + DATE_LEN])?.enforce_cmp(
            &today,
            core::cmp::Ordering::Greater,
            false,
        )?;

        // Check that the attr's name, nationality, and DOB match the passport's
        dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN]
            .enforce_equal(&attrs.nationality.0)?;
        dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN].enforce_equal(&attrs.name.0)?;
        date_to_field_elem(&dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN])?.enforce_equal(&attrs.dob)?;

        // Check pre-econtent structure, and check that the biometric hash matches the passport's
        let dg1_hash = Sha256Gadget::digest(&dg1)?;
        let dg2_hash = &attrs.biometric_hash.0;
        pre_econtent[DG1_HASH_OFFSET..DG1_HASH_OFFSET + HASH_LEN].enforce_equal(&dg1_hash.0)?;
        pre_econtent[DG2_HASH_OFFSET..DG2_HASH_OFFSET + HASH_LEN].enforce_equal(dg2_hash)?;

        // Check the econtent structure
        let pre_econtent_hash = Sha256Gadget::digest(&pre_econtent)?;
        econtent[PRE_ECONTENT_HASH_OFFSET..PRE_ECONTENT_HASH_OFFSET + HASH_LEN]
            .enforce_equal(&pre_econtent_hash.0)?;

        // Check the econtent hash matches the passport's
        econtent_hash.enforce_equal(&Sha256Gadget::digest(&econtent)?.0)?;

        // All done
        Ok(())
    }

    // The public inputs are: econtent_hash, expected_issuer, today
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.econtent_hash.to_field_elements().unwrap(),
            self.expected_issuer.to_field_elements().unwrap(),
            vec![self.today],
        ]
        .concat()
    }
}
