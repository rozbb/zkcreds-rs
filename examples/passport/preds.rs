use crate::{
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
pub(crate) struct AgeAndFaceChecker {
    // Verifier-chosen values
    pub(crate) threshold_dob: Fr,

    // Public inputs
    pub(crate) face_hash: [u8; HASH_LEN],
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
        let threshold_dob =
            FpVar::<Fr>::new_input(ns!(cs, "threshold year"), || Ok(self.threshold_dob))?;
        let face_hash = UInt8::new_input_vec(ns!(cs, "face hash"), &self.face_hash)?;

        // Assert that attrs.dob ≤ threshold_dob
        attrs
            .dob
            .enforce_cmp(&threshold_dob, core::cmp::Ordering::Less, true)?;

        // Assert that the given face hash is the same as the attr's biometric hash
        face_hash.enforce_equal(&attrs.biometric_hash.0)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        [
            vec![self.threshold_dob],
            self.face_hash.to_field_elements().unwrap(),
        ]
        .concat()
    }
}
