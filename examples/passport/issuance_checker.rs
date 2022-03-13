use crate::{
    ark_sha256::Sha256Gadget,
    params::{
        Fr, PassportComScheme, PassportComSchemeG, PredProof, DATE_LEN, DG1_HASH_OFFSET, DG1_LEN,
        DG2_HASH_OFFSET, DOB_OFFSET, ECONTENT_LEN, EXPIRY_OFFSET, HASH_LEN, ISSUER_OFFSET,
        NAME_LEN, NAME_OFFSET, NATIONALITY_OFFSET, PRE_ECONTENT_HASH_OFFSET, PRE_ECONTENT_LEN,
        SIG_HASH_LEN, STATE_ID_LEN,
    },
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
};

use zeronym::{pred::PredicateChecker, Com};

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use sha2::{Digest, Sha256};

/// A request to issue attrs_com. This is includes a proof that opens the attrs and a signature
/// over the corresponding passport's econtent hash
pub(crate) struct IssuanceReq {
    pub(crate) attrs_com: Com<PassportComScheme>,
    pub(crate) econtent_hash: [u8; HASH_LEN],
    pub(crate) sig: Vec<u8>,
    pub(crate) hash_proof: PredProof,
}

/// Verifies that the given passport contents hashes to the correct `econtent_hash`, and that the
/// provided `PersonalInfo` corresponds to its contents.
#[derive(Clone)]
pub(crate) struct PassportHashChecker {
    // Public inputs
    econtent_hash: [u8; SIG_HASH_LEN],
    expected_issuer: [u8; STATE_ID_LEN],
    today: Fr,
    max_valid_years: Fr,

    // Private inputs
    dg1: [u8; DG1_LEN],
    pre_econtent: [u8; PRE_ECONTENT_LEN],
    econtent: [u8; ECONTENT_LEN],
}

impl Default for PassportHashChecker {
    fn default() -> PassportHashChecker {
        PassportHashChecker {
            econtent_hash: [0u8; SIG_HASH_LEN],
            expected_issuer: [0u8; STATE_ID_LEN],
            today: Fr::default(),
            max_valid_years: Fr::default(),
            dg1: [0u8; DG1_LEN],
            pre_econtent: [0u8; PRE_ECONTENT_LEN],
            econtent: [0u8; ECONTENT_LEN],
        }
    }
}

impl PassportHashChecker {
    /// Makes an issuance checker given a passport, 3-letter issuing state, and today's date in the
    /// form YYYYMMDD in base-10 (this is to check DOB). `max_valid_years` is the longest that a
    /// document can be valid, in years.
    pub(crate) fn from_passport(
        dump: &PassportDump,
        expected_issuer: [u8; STATE_ID_LEN],
        today: u32,
        max_valid_years: u32,
    ) -> PassportHashChecker {
        let mut dg1 = [0u8; DG1_LEN];
        let mut pre_econtent = [0u8; PRE_ECONTENT_LEN];
        let mut econtent = [0u8; ECONTENT_LEN];
        let mut econtent_hash = [0u8; SIG_HASH_LEN];

        dg1.copy_from_slice(&dump.dg1);
        pre_econtent.copy_from_slice(&dump.pre_econtent);
        econtent.copy_from_slice(&dump.econtent);
        econtent_hash.copy_from_slice(&Sha256::digest(econtent));

        PassportHashChecker {
            econtent_hash,
            expected_issuer,
            today: Fr::from(today),
            max_valid_years: Fr::from(max_valid_years),
            dg1,
            pre_econtent,
            econtent,
        }
    }

    /// Makes an issuance checker given an issuance request, a 3-letter issuing state, and today's
    /// date in the form YYYYMMDD in base-10 (this is to check expiry).  `max_valid_years` is the
    /// longest that a document can be valid, in years.
    pub(crate) fn from_issuance_req(
        req: &IssuanceReq,
        expected_issuer: [u8; STATE_ID_LEN],
        today: u32,
        max_valid_years: u32,
    ) -> PassportHashChecker {
        PassportHashChecker {
            econtent_hash: req.econtent_hash,
            expected_issuer,
            today: Fr::from(today),
            max_valid_years: Fr::from(max_valid_years),
            ..Default::default()
        }
    }
}

/// Converts a date string of the form YYMMDD to a field element whose canonical base-10
/// representation is YYYYMMDD. `not_after` is the soonest day in the 21st century after which the
/// input would not make sense, e.g., a birthdate wouldn't make sense if it were after today, and a
/// document expiry date wouldn't be 20 years in the future.
fn date_to_field_elem(
    date: &[UInt8<Fr>],
    not_after: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    assert_eq!(date.len(), DATE_LEN);

    // Constants
    let ten = Fr::from(10u16);
    let zero = FpVar::Constant(Fr::from(0u32));
    let century = FpVar::Constant(Fr::from(1000000u32));
    let twenty_first_century = &century * Fr::from(20u32);

    // Converts ASCII numbers to the numbers they represent. E.g., int(b"9") = 9 (mod |Fr|)
    fn int(char: &UInt8<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        let char_fp = Boolean::le_bits_to_fp_var(char.to_bits_le()?.as_slice())?;
        Ok(char_fp - Fr::from(48u16))
    }

    // Convert the year, month, and day separately. b"YY" becomes YY (mod |Fr|), etc.
    let year = (int(&date[0])? * ten) + int(&date[1])?;
    let month = (int(&date[2])? * ten) + int(&date[3])?;
    let day = (int(&date[4])? * ten) + int(&date[5])?;

    // Now combine the values by shifting and adding. The year is only given as YY so we don't
    // immediately have the most significant digits of the year. Assume for now that it's the 21st
    // century
    let mut d =
        twenty_first_century + (year * Fr::from(10000u16)) + (month * Fr::from(100u16)) + day;

    // If the date is not from the 21st century, then d will be in the future. If that's the case
    // remove 100 years
    let overshot_century = d.is_cmp(not_after, core::cmp::Ordering::Greater, false)?;
    let delta = CondSelectGadget::conditionally_select(&overshot_century, &century, &zero)?;
    // Subtract the delta, which is 100 iff we overshot the century
    d -= delta;

    Ok(d)
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for PassportHashChecker
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
        let today = FpVar::<Fr>::new_input(ns!(cs, "DOB threshold"), || Ok(self.today))?;
        let max_valid_years =
            FpVar::<Fr>::new_input(ns!(cs, "max valid years"), || Ok(self.max_valid_years))?;

        // The earliest time after which expiry doesn't make sense. This is used to parse the
        // underdefined date format in the passport
        let expiry_not_after = today.clone() + max_valid_years * Fr::from(10000u32);
        // The earliest time after which DOB doesn't make sense. This is precisely today, since you
        // can't be born in the future >.>
        let dob_not_after = today.clone();

        // Witness private inputs
        let dg1 = UInt8::new_witness_vec(ns!(cs, "dg1"), &self.dg1)?;
        let pre_econtent = UInt8::new_witness_vec(ns!(cs, "pre-econtent"), &self.pre_econtent)?;
        let econtent = UInt8::new_witness_vec(ns!(cs, "econtent"), &self.econtent)?;

        // Check that the issuer is the expected one, and the passport isn't expired
        dg1[ISSUER_OFFSET..ISSUER_OFFSET + STATE_ID_LEN].enforce_equal(&expected_issuer)?;
        let expiry = date_to_field_elem(
            &dg1[EXPIRY_OFFSET..EXPIRY_OFFSET + DATE_LEN],
            &expiry_not_after,
        )?;
        expiry.enforce_cmp(&today, core::cmp::Ordering::Greater, false)?;

        // Check that the attr's name, nationality, and DOB match the passport's
        dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN]
            .enforce_equal(&attrs.nationality.0)?;
        dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN].enforce_equal(&attrs.name.0)?;
        let dob = date_to_field_elem(&dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN], &dob_not_after)?;
        dob.enforce_equal(&attrs.dob)?;

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
            vec![self.max_valid_years],
        ]
        .concat()
    }
}
