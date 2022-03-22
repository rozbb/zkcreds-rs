use crate::passport::{
    params::{Fr, PassportComScheme, PassportComSchemeG, HASH_LEN},
    passport_info::{PersonalInfo, PersonalInfoVar},
};

use zeronym::pred::PredicateChecker;

use ark_ff::ToConstraintField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, uint8::UInt8};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

#[derive(Clone, Default)]
pub(crate) struct AgeFaceExpiryChecker {
    // Verifier-chosen values
    pub(crate) threshold_dob: Fr,
    pub(crate) threshold_expiry: Fr,

    // Public inputs
    pub(crate) face_hash: [u8; HASH_LEN],
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeFaceExpiryChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // Witness as public inputs the threshold DOB, threshold expiry date, face hash
        let threshold_dob =
            FpVar::<Fr>::new_input(ns!(cs, "threshold dob"), || Ok(self.threshold_dob))?;
        let threshold_expiry =
            FpVar::<Fr>::new_input(ns!(cs, "threshold expiry"), || Ok(self.threshold_expiry))?;
        let face_hash = UInt8::new_input_vec(ns!(cs, "face hash"), &self.face_hash)?;

        // Assert that attrs.dob ≤ threshold_dob
        attrs
            .dob
            .enforce_cmp(&threshold_dob, core::cmp::Ordering::Less, true)?;
        // Assert that attrs.passport_expiry > threshold_expiry
        attrs.passport_expiry.enforce_cmp(
            &threshold_expiry,
            core::cmp::Ordering::Greater,
            false,
        )?;

        // Assert that the given face hash is the same as the attr's biometric hash
        face_hash.enforce_equal(&attrs.biometric_hash.0)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        [
            vec![self.threshold_dob],
            vec![self.threshold_expiry],
            self.face_hash.to_field_elements().unwrap(),
        ]
        .concat()
    }
}

#[derive(Clone, Default)]
pub(crate) struct AgeAndExpiryChecker {
    // Verifier-chosen values
    pub(crate) threshold_dob: Fr,
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeAndExpiryChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // Witness as public inputs the threshold DOB, threshold expiry date, face hash
        let threshold_dob =
            FpVar::<Fr>::new_input(ns!(cs, "threshold dob"), || Ok(self.threshold_dob))?;
        let threshold_expiry =
            FpVar::<Fr>::new_input(ns!(cs, "threshold expiry"), || Ok(self.threshold_expiry))?;

        // Assert that attrs.dob ≤ threshold_dob
        attrs
            .dob
            .enforce_cmp(&threshold_dob, core::cmp::Ordering::Less, true)?;
        // Assert that attrs.passport_expiry > threshold_expiry
        attrs.passport_expiry.enforce_cmp(
            &threshold_expiry,
            core::cmp::Ordering::Greater,
            false,
        )?;

        Ok(())
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        [vec![self.threshold_dob], vec![self.threshold_expiry]].concat()
    }
}
