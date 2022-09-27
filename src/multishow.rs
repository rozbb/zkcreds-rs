//! Defines a trait that allows service providers to implement rate limiting on their services

use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar},
    pred::PredicateChecker,
};

use core::cmp::Ordering;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    Error as ArkError,
};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, ToConstraintFieldGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon, PoseidonParameters};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget, PoseidonParametersVar};

// Domain separators for all our uses of Poseidon
const PRF1_DOMAIN_SEP: u8 = 123;

/// A pseudorandom pair of field elements. If there are ever two tokens with the same `hidden_ctr`,
/// they can be combined to derive the (hash of the) user's ID.
#[derive(Clone, Default)]
pub struct PresentationToken<ConstraintF: PrimeField> {
    /// This is `PRFₛ(epoch || ctr)` where s is the seed
    hidden_ctr: ConstraintF,
}

/// The variable version of presentation token
#[derive(Clone)]
pub struct PresentationTokenVar<ConstraintF: PrimeField> {
    hidden_ctr: FpVar<ConstraintF>,
}

/// This trait allows a user to create a "presentation token" every time they show their
/// credential. This can be used for rate limiting if the verifier requires that `ctr` is bounded
/// for every `epoch`.
pub trait MultishowableAttrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Computes the presentation token from the given accountable attribute
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
        epoch: u64,
        ctr: u16,
    ) -> Result<PresentationToken<ConstraintF>, ArkError>;
}

impl<ConstraintF, A, AC> MultishowableAttrs<ConstraintF, AC> for A
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Computes the presentation token from the given accountable attribute
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
        epoch: u64,
        ctr: u16,
    ) -> Result<PresentationToken<ConstraintF>, ArkError> {
        let h = Poseidon::new(params);
        let seed = self.get_seed();

        // hidden_ctr = PRFₛ(epoch || ctr)
        let hidden_ctr: ConstraintF = {
            let hash_input = &[
                vec![ConstraintF::from(PRF1_DOMAIN_SEP)],
                seed.to_field_elements().unwrap(),
                vec![ConstraintF::from(epoch), ConstraintF::from(ctr)],
            ]
            .concat();

            h.hash(hash_input).unwrap()
        };

        Ok(PresentationToken { hidden_ctr })
    }
}

/// Implements `compute_presentation_token` for all AccountableAttrsVar
pub trait MultishowableAttrsVar<ConstraintF, A, AC, ACG>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    /// Computes the presentation token from the given accountable attribute
    fn compute_presentation_token(
        &self,
        params: PoseidonParametersVar<ConstraintF>,
        epoch: &FpVar<ConstraintF>,
        ctr: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError>;
}

/// Implements `compute_presentation_token` for all AccountableAttrsVar
impl<ConstraintF, A, AV, AC, ACG> MultishowableAttrsVar<ConstraintF, A, AC, ACG> for AV
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AV: AccountableAttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    /// Computes the presentation token from the given accountable attribute
    fn compute_presentation_token(
        &self,
        params: PoseidonParametersVar<ConstraintF>,
        epoch: &FpVar<ConstraintF>,
        ctr: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError> {
        let h = PoseidonGadget { params };
        let seed = self.get_seed()?;

        // hidden_ctr = PRFₛ(epoch || ctr)
        let hidden_ctr = {
            let hash_input = [
                vec![FpVar::Constant(ConstraintF::from(PRF1_DOMAIN_SEP))],
                seed.to_constraint_field()?,
                epoch.to_constraint_field()?,
                ctr.to_constraint_field()?,
            ]
            .concat();

            h.hash(&hash_input)?
        };

        Ok(PresentationTokenVar { hidden_ctr })
    }
}

/// Proves that `token` is the result of a PRF computation using the random seed
#[derive(Clone, Default)]
pub struct MultishowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
{
    // Public inputs //
    /// The psuedorandom values associated with this presentation
    pub token: PresentationToken<ConstraintF>,
    // The current show epoch
    pub epoch: u64,
    /// Number of times this attrribute string can be shown
    pub max_num_presentations: u16,

    // Private inputs //
    /// The counter representing the number of times this attribute string has been shown so far
    /// (begins at 0)
    pub ctr: u16,

    // Constants //
    /// Poseidon parameters
    pub params: PoseidonParameters<ConstraintF>,
}

impl<ConstraintF, A, AV, AC, ACG> PredicateChecker<ConstraintF, A, AV, AC, ACG>
    for MultishowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AV: AccountableAttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Returns whether or not the predicate was satisfied
    fn pred(self, cs: ConstraintSystemRef<ConstraintF>, attrs: &AV) -> Result<(), SynthesisError> {
        // Witness the Poseidon params
        let params = PoseidonParametersVar::new_constant(ns!(cs, "prf param"), &self.params)?;

        // Witness public inputs: epoch, nonce, token, and max counter size
        let epoch = FpVar::<ConstraintF>::new_input(ns!(cs, "epoch"), || {
            Ok(ConstraintF::from(self.epoch))
        })?;
        let hidden_ctr =
            FpVar::<ConstraintF>::new_input(ns!(cs, "hidden ctr"), || Ok(self.token.hidden_ctr))?;
        let max_num_presentations =
            FpVar::<ConstraintF>::new_input(ns!(cs, "max #presentations"), || {
                Ok(ConstraintF::from(self.max_num_presentations))
            })?;

        // Witness the counter private input
        let ctr =
            FpVar::<ConstraintF>::new_witness(ns!(cs, "ctr"), || Ok(ConstraintF::from(self.ctr)))?;

        // Assert counter < max_num_presentations
        ctr.enforce_cmp(&max_num_presentations, Ordering::Less, false)?;

        // Compute the presentation token
        let computed_token = attrs.compute_presentation_token(params, &epoch, &ctr)?;

        // Assert the equality of the computed values
        computed_token.hidden_ctr.enforce_equal(&hidden_ctr)?;

        // All done
        Ok(())
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<ConstraintF> {
        vec![
            self.epoch.into(),
            self.token.hidden_ctr,
            self.max_num_presentations.into(),
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attrs::Attrs,
        poseidon_utils::setup_poseidon_params,
        pred::{gen_pred_crs, prove_birth, verify_birth},
        test_util::{
            NameAndBirthYear, NameAndBirthYearVar, TestComSchemePedersen, TestComSchemePedersenG,
            TestTreeH, TestTreeHG,
        },
    };

    use ark_bls12_381::Bls12_381 as E;
    use arkworks_utils::Curve;

    const POSEIDON_WIDTH: u8 = 5;

    #[test]
    fn test_multishow() {
        let mut rng = ark_std::test_rng();

        // Set up the public parameters
        let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
        let epoch = 5;
        let max_num_presentations: u16 = 128;
        let placeholder_checker = MultishowChecker {
            params: params.clone(),
            ..Default::default()
        };
        let pk = gen_pred_crs::<
            _,
            _,
            E,
            _,
            NameAndBirthYearVar,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, placeholder_checker)
        .unwrap();

        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);

        // User computes a multishow token
        let ctr: u16 = 1;
        let token = MultishowableAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
            &person,
            params.clone(),
            epoch,
            ctr,
        )
        .unwrap();

        // User constructs a checker for their predicate
        let users_checker = MultishowChecker {
            token: token.clone(),
            epoch,
            max_num_presentations,
            ctr,
            params: params.clone(),
        };

        // Prove the predicate
        let proof = prove_birth(&mut rng, &pk, users_checker, person.clone()).unwrap();

        // Now verify the predicate
        // Make the checker with only the public data
        let verifiers_checker = MultishowChecker {
            token,
            epoch,
            max_num_presentations,
            params,
            ..Default::default()
        };
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &verifiers_checker, &person_com).unwrap());
    }
}
