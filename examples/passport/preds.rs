use crate::{
    params::{Fr, PassportComScheme, PassportComSchemeG},
    passport_info::{PersonalInfo, PersonalInfoVar},
};

use zeronym::pred::PredicateChecker;

use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, uint8::UInt8};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

#[derive(Clone)]
pub(crate) struct AgeAndFaceChecker {
    pub(crate) threshold_birth_year: Fr,
    pub(crate) face_hash: Vec<u8>,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeAndFaceChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // Witness the threshold year and face hash as public inputs
        let threshold_birth_year =
            FpVar::<Fr>::new_input(ns!(cs, "threshold year"), || Ok(self.threshold_birth_year))?;
        let face_hash = UInt8::new_input_vec(ns!(cs, "face hash"), &self.face_hash)?;

        // Assert that attrs.birth_year ≤ threshold_birth_year
        attrs
            .dob
            .enforce_cmp(&threshold_birth_year, core::cmp::Ordering::Less, true)?;

        // Assert that the given face hash is the same as the attr's biometric hash
        face_hash.enforce_equal(&attrs.biometric_hash.0)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_birth_year]
    }
}
