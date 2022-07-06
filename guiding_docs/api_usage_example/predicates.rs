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
