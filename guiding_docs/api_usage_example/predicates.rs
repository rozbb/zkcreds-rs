/// Checks the age of a PersonalInfo
struct AgeChecker {
    threshold_dob: Fr,
}

/// Checks the expiry of a PersonalInfo
struct ExpiryChecker {
    threshold_expiry: Fr,
}

/// Checks that the given face hash appears in a PersonalInfo
struct FaceChecker {
    face_hash: [u8; HASH_LEN],
}

/// An issuance predicate that verifies that the given passport contents hashes to the correct
/// `econtent_hash`, and that the provided `PersonalInfo` corresponds to its contents.
struct PassportHashChecker {
    // Public inputs
    econtent_hash: [u8; SIG_HASH_LEN],
    expected_issuer: [u8; STATE_ID_LEN],
    today: FieldElem,
    max_valid_years: FieldElem,

    // Private inputs
    dg1: [u8; DG1_LEN],
    pre_econtent: [u8; PRE_ECONTENT_LEN],
    econtent: [u8; ECONTENT_LEN],
}

// Make AgeChecker a predicate over PeronsalInfo
impl PredicateChecker<PersonalInfo> for AgeChecker {
    type AttrsVar = PersonalInfoVar;

    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &Self::AttrsVar,
    ) -> Result<(), SynthesisError> {
        // Assert that attrs.dob ≤ threshold_dob
        let threshold_dob =
            FpVar::<Fr>::new_input(ns!(cs, "threshold dob"), || Ok(self.threshold_dob))?;
        attrs
            .dob
            .enforce_cmp(&threshold_dob, core::cmp::Ordering::Less, true)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_dob]
    }
}

// Make ExpiryChecker a predicate over PeronsalInfo
// [omitted]; this is nearly identical to that of AgeChecker

// Make FaceChecker a predicate over PersonalInfo
impl PredicateChecker<PersonalInfo> for FaceChecker {
    type AttrsVar = PersonalInfoVar;

    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &Self::AttrsVar,
    ) -> Result<(), SynthesisError> {
        // Assert that the given face hash is the same as the attr's biometric hash
        let face_hash = UInt8::new_input_vec(ns!(cs, "face hash"), &self.face_hash)?;
        face_hash.enforce_equal(&attrs.biometric_hash.0)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        self.face_hash.to_field_elements().unwrap()
    }
}

//
// Now the big one, defining the passport hash checker
//

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
