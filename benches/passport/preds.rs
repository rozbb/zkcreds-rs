use crate::passport::{
    params::{Fr, PassportComScheme, PassportComSchemeG, HASH_LEN},
    passport_info::{PersonalInfo, PersonalInfoVar},
};

use zkcreds::{pred::PredicateChecker, revealing_multishow::RevealingMultishowChecker};

use ark_ff::ToConstraintField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, uint8::UInt8};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

#[derive(Clone, Default)]
pub(crate) struct AgeChecker {
    pub(crate) threshold_dob: Fr,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
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

#[derive(Clone, Default)]
pub(crate) struct ExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for ExpiryChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // Assert that attrs.passport_expiry > threshold_expiry
        let threshold_expiry =
            FpVar::<Fr>::new_input(ns!(cs, "threshold expiry"), || Ok(self.threshold_expiry))?;
        attrs
            .passport_expiry
            .enforce_cmp(&threshold_expiry, core::cmp::Ordering::Greater, false)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}

#[derive(Clone, Default)]
pub(crate) struct FaceChecker {
    pub(crate) face_hash: [u8; HASH_LEN],
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for FaceChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
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

#[derive(Clone, Default)]
pub(crate) struct AgeFaceExpiryChecker {
    pub(crate) age_checker: AgeChecker,
    pub(crate) face_checker: FaceChecker,
    pub(crate) expiry_checker: ExpiryChecker,
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
        self.age_checker.pred(cs.clone(), attrs)?;
        self.face_checker.pred(cs.clone(), attrs)?;
        self.expiry_checker.pred(cs.clone(), attrs)?;

        Ok(())
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.age_checker.public_inputs(),
            self.face_checker.public_inputs(),
            self.expiry_checker.public_inputs(),
        ]
        .concat()
    }
}

#[derive(Clone, Default)]
pub(crate) struct AgeAndExpiryChecker {
    pub(crate) age_checker: AgeChecker,
    pub(crate) expiry_checker: ExpiryChecker,
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
        self.age_checker.pred(cs.clone(), attrs)?;
        self.expiry_checker.pred(cs.clone(), attrs)?;

        Ok(())
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.age_checker.public_inputs(),
            self.expiry_checker.public_inputs(),
        ]
        .concat()
    }
}

#[derive(Clone, Default)]
pub(crate) struct AgeMultishowExpiryChecker {
    pub(crate) age_checker: AgeChecker,
    pub(crate) multishow_checker: RevealingMultishowChecker<Fr>,
    pub(crate) expiry_checker: ExpiryChecker,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeMultishowExpiryChecker
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        self.age_checker.pred(cs.clone(), attrs)?;
        self.multishow_checker.pred(cs.clone(), attrs)?;
        self.expiry_checker.pred(cs.clone(), attrs)?;

        Ok(())
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.age_checker.public_inputs(),
            <RevealingMultishowChecker<Fr> as PredicateChecker<
                Fr,
                PersonalInfo,
                PersonalInfoVar,
                PassportComScheme,
                PassportComSchemeG,
            >>::public_inputs(&self.multishow_checker),
            self.expiry_checker.public_inputs(),
        ]
        .concat()
    }
}
