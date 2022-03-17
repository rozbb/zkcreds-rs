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
use arkworks_native_gadgets::poseidon::{
    sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters,
};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget, PoseidonParametersVar};
use arkworks_utils::{bytes_matrix_to_f, bytes_vec_to_f, Curve};

// Domain separators for all our uses of Poseidon
const PRF1_DOMAIN_SEP: u8 = 123;
const PRF2_DOMAIN_SEP: u8 = 124;
const HASH_DOMAIN_SEP: u8 = 125;

/// A pseudorandom pair of field elements. If there are ever two tokens with the same `hidden_ctr`,
/// they can be combined to derive the (hash of the) user's ID.
#[derive(Clone, Default)]
pub struct PresentationToken<ConstraintF: PrimeField> {
    /// This is `PRFₛ(ctr)` where s is the seed
    hidden_ctr: ConstraintF,

    /// This is `H(ID) + H(n)·PRFₛ'(ctr)` where `ID` is the user ID, s is the seed, and n is the
    /// presentation nonce. Notice that if `ctr` repeats then we have two elements on the line
    /// `H(ID) + x·PRFₛ'(ctr)`. An observer can solve for the y-intercept and recover `H(ID)`.
    hidden_line_point: ConstraintF,
}

/// The variable version of presentation token
#[derive(Clone)]
pub struct PresentationTokenVar<ConstraintF: PrimeField> {
    hidden_ctr: FpVar<ConstraintF>,
    hidden_line_point: FpVar<ConstraintF>,
}

/// Implements `compute_presentation_token` for all AccountableAttrs
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
        ctr: u16,
        nonce: ConstraintF,
    ) -> Result<PresentationToken<ConstraintF>, ArkError>;
}

/// Implements `compute_presentation_token` for all AccountableAttrs
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
        ctr: u16,
        nonce: ConstraintF,
    ) -> Result<PresentationToken<ConstraintF>, ArkError> {
        let h = Poseidon::new(params);
        let id = self.get_id();
        let seed = self.get_seed();

        // hidden_ctr = PRFₛ(ctr)
        let hidden_ctr: ConstraintF = {
            let hash_input = &[
                vec![ConstraintF::from(PRF1_DOMAIN_SEP)],
                seed.to_field_elements().unwrap(),
                vec![ConstraintF::from(ctr)],
            ]
            .concat();

            h.hash(hash_input).unwrap()
        };

        // hidden_line_point = H(ID) + H(nonce)·PRFₛ'(ctr)
        let hidden_line_point = {
            // First hash the nonce
            let nonce_hash = {
                let hash_input = [
                    vec![ConstraintF::from(HASH_DOMAIN_SEP)],
                    nonce.to_field_elements().unwrap(),
                ]
                .concat();

                h.hash(&hash_input).unwrap()
            };

            // Then hash the ID
            let id_hash = {
                let hash_input = [
                    vec![ConstraintF::from(HASH_DOMAIN_SEP)],
                    id.to_field_elements().unwrap(),
                ]
                .concat();

                h.hash(&hash_input).unwrap()
            };

            // Now compute PRFₛ'(ctr)
            let prf_value = {
                let hash_input = [
                    vec![ConstraintF::from(PRF2_DOMAIN_SEP)],
                    seed.to_field_elements().unwrap(),
                    vec![ConstraintF::from(ctr)],
                ]
                .concat();

                h.hash(&hash_input).unwrap()
            };

            // Now put it together
            id_hash + nonce_hash * prf_value
        };

        Ok(PresentationToken {
            hidden_ctr,
            hidden_line_point,
        })
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
        ctr: &FpVar<ConstraintF>,
        nonce: &FpVar<ConstraintF>,
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
        ctr: &FpVar<ConstraintF>,
        nonce: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError> {
        let h = PoseidonGadget { params };
        let id = self.get_id()?;
        let seed = self.get_seed()?;

        // hidden_ctr = PRFₛ(ctr)
        let hidden_ctr = {
            let hash_input = [
                vec![FpVar::Constant(ConstraintF::from(PRF1_DOMAIN_SEP))],
                seed.to_constraint_field()?,
                ctr.to_constraint_field()?,
            ]
            .concat();

            h.hash(&hash_input)?
        };

        // hidden_line_point = H(ID) + H(nonce)·PRFₛ'(ctr)
        let hidden_line_point = {
            // First hash the nonce
            let nonce_hash = {
                let hash_input = [
                    vec![FpVar::Constant(ConstraintF::from(HASH_DOMAIN_SEP))],
                    nonce.to_constraint_field()?,
                ]
                .concat();

                h.hash(&hash_input)?
            };

            // Then hash the ID
            let id_hash = {
                let hash_input = [
                    vec![FpVar::Constant(ConstraintF::from(HASH_DOMAIN_SEP))],
                    id.to_constraint_field()?,
                ]
                .concat();

                h.hash(&hash_input)?
            };

            // Now compute PRFₛ'(ctr)
            let prf_value = {
                let hash_input = [
                    vec![FpVar::Constant(ConstraintF::from(PRF2_DOMAIN_SEP))],
                    seed.to_constraint_field()?,
                    ctr.to_constraint_field()?,
                ]
                .concat();

                h.hash(&hash_input)?
            };

            // Now put it together
            id_hash + nonce_hash * prf_value
        };

        Ok(PresentationTokenVar {
            hidden_ctr,
            hidden_line_point,
        })
    }
}

/// Proves that `token` is the result of a PRF computation using the verifier-provided nonce and
/// the attribute's ID and random seed
#[derive(Clone, Default)]
pub struct RevealingMultishowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
{
    // Public inputs //
    /// The psuedorandom values associated with this presentation
    pub token: PresentationToken<ConstraintF>,
    // The nonce provided by the server
    pub nonce: ConstraintF,
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
    for RevealingMultishowChecker<ConstraintF>
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

        // Witness public inputs: nonce, token, and max counter size
        let nonce = FpVar::<ConstraintF>::new_input(ns!(cs, "nonce"), || Ok(self.nonce))?;
        let hidden_ctr =
            FpVar::<ConstraintF>::new_input(ns!(cs, "hidden ctr"), || Ok(self.token.hidden_ctr))?;
        let hidden_line_point =
            FpVar::<ConstraintF>::new_input(ns!(cs, "hidden line point"), || {
                Ok(self.token.hidden_line_point)
            })?;
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
        let computed_token = attrs.compute_presentation_token(params, &ctr, &nonce)?;

        // Assert the equality of the computed values
        computed_token.hidden_ctr.enforce_equal(&hidden_ctr)?;
        computed_token
            .hidden_line_point
            .enforce_equal(&hidden_line_point)?;

        // All done
        Ok(())
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<ConstraintF> {
        vec![
            self.nonce,
            self.token.hidden_ctr,
            self.token.hidden_line_point,
            self.max_num_presentations.into(),
        ]
    }
}

pub fn setup_poseidon_params<F: PrimeField>(
    curve: Curve,
    exp: i8,
    width: u8,
) -> PoseidonParameters<F> {
    let pos_data =
        arkworks_utils::poseidon_params::setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    PoseidonParameters {
        mds_matrix: mds_f,
        round_keys: rounds_f,
        full_rounds: pos_data.full_rounds,
        partial_rounds: pos_data.partial_rounds,
        sbox: PoseidonSbox(pos_data.exp),
        width: pos_data.width,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attrs::Attrs,
        pred::{gen_pred_crs, prove_birth, verify_birth},
        test_util::{NameAndBirthYear, NameAndBirthYearVar, TestTreeH, TestTreeHG},
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ff::UniformRand;
    use arkworks_utils::Curve;

    const POSEIDON_WIDTH: u8 = 5;

    #[test]
    fn test_revealing_multishow() {
        let mut rng = ark_std::test_rng();

        // Set up the public parameters
        let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
        let max_num_presentations: u16 = 128;
        let placeholder_checker = RevealingMultishowChecker {
            params: params.clone(),
            ..Default::default()
        };
        let pk = gen_pred_crs::<_, _, E, _, NameAndBirthYearVar, _, _, TestTreeH, TestTreeHG>(
            &mut rng,
            placeholder_checker,
        )
        .unwrap();

        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);

        // User computes a multishow token
        let nonce = Fr::rand(&mut rng);
        let ctr: u16 = 1;
        let token = person
            .compute_presentation_token(params.clone(), ctr, nonce)
            .unwrap();

        // User constructs a checker for their predicate
        let users_checker = RevealingMultishowChecker {
            token: token.clone(),
            nonce,
            max_num_presentations,
            ctr,
            params: params.clone(),
        };

        // Prove the predicate
        let proof = prove_birth(&mut rng, &pk, users_checker, person.clone()).unwrap();

        // Now verify the predicate
        // Make the checker with only the public data
        let verifiers_checker = RevealingMultishowChecker {
            token,
            nonce,
            max_num_presentations,
            params,
            ..Default::default()
        };
        let person_com = person.commit();
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &verifiers_checker, &person_com).unwrap());
    }
}
