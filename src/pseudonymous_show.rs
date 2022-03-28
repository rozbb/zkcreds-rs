use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar},
    pred::PredicateChecker,
};

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
    /// This is `PRFₛ(0)` where s is the seed
    pseudonym: ConstraintF,
}

/// The variable version of presentation token
#[derive(Clone)]
pub struct PresentationTokenVar<ConstraintF: PrimeField> {
    pseudonym: FpVar<ConstraintF>,
}

/// Implements `compute_presentation_token` for all AccountableAttrs
pub trait PseudonymousAttrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Computes the presentation token from the given accountable attribute
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
    ) -> Result<PresentationToken<ConstraintF>, ArkError>;
}

/// Implements `compute_presentation_token` for all AccountableAttrs
impl<ConstraintF, A, AC> PseudonymousAttrs<ConstraintF, AC> for A
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
    ) -> Result<PresentationToken<ConstraintF>, ArkError> {
        let h = Poseidon::new(params);
        let seed = self.get_seed();

        // hidden_ctr = PRFₛ(0)
        let pseudonym: ConstraintF = {
            let hash_input = [
                vec![ConstraintF::from(PRF1_DOMAIN_SEP)],
                seed.to_field_elements().unwrap(),
                vec![ConstraintF::from(0u8)],
            ]
            .concat();
            h.hash(&hash_input).unwrap()
        };

        Ok(PresentationToken { pseudonym })
    }
}

/// Implements `compute_presentation_token` for all AccountableAttrsVar
pub trait PseudonymousAttrsVar<ConstraintF, A, AC, ACG>
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
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError>;
}

/// Implements `compute_presentation_token` for all AccountableAttrsVar
impl<ConstraintF, A, AV, AC, ACG> PseudonymousAttrsVar<ConstraintF, A, AC, ACG> for AV
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
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError> {
        let h = PoseidonGadget { params };
        let seed = self.get_seed()?;

        // pseudonym = PRFₛ(0)
        let pseudonym = {
            let hash_input = [
                vec![FpVar::Constant(ConstraintF::from(PRF1_DOMAIN_SEP))],
                seed.to_constraint_field()?,
                vec![FpVar::Constant(ConstraintF::from(0u8))],
            ]
            .concat();

            h.hash(&hash_input)?
        };

        Ok(PresentationTokenVar { pseudonym })
    }
}

/// Proves that `token` is the result of a PRF computation using the verifier-provided nonce and
/// the attribute's ID and random seed
#[derive(Clone, Default)]
pub struct PseudonymousShowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
{
    // Public inputs //
    /// The psuedorandom values associated with all presentations of this cred
    pub token: PresentationToken<ConstraintF>,

    // Constants //
    /// Poseidon parameters
    pub params: PoseidonParameters<ConstraintF>,
}

impl<ConstraintF, A, AV, AC, ACG> PredicateChecker<ConstraintF, A, AV, AC, ACG>
    for PseudonymousShowChecker<ConstraintF>
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

        // Witness public input
        let pseudonym =
            FpVar::<ConstraintF>::new_input(ns!(cs, "pseudonym"), || Ok(self.token.pseudonym))?;

        // Compute the presentation token
        let computed_token = attrs.compute_presentation_token(params)?;

        // Assert the equality of the computed values
        computed_token.pseudonym.enforce_equal(&pseudonym)?;

        // All done
        Ok(())
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<ConstraintF> {
        vec![self.token.pseudonym]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attrs::Attrs,
        pred::{gen_pred_crs, prove_birth, verify_birth},
        test_util::{NameAndBirthYear, NameAndBirthYearVar, TestTreeH, TestTreeHG},
        utils::setup_poseidon_params,
    };

    use ark_bls12_381::Bls12_381 as E;
    use arkworks_utils::Curve;

    const POSEIDON_WIDTH: u8 = 5;

    #[test]
    fn test_pseudonymous_show() {
        let mut rng = ark_std::test_rng();

        // Set up the public parameters
        let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
        let placeholder_checker = PseudonymousShowChecker {
            params: params.clone(),
            ..Default::default()
        };
        let pk = gen_pred_crs::<_, _, E, _, NameAndBirthYearVar, _, _, TestTreeH, TestTreeHG>(
            &mut rng,
            placeholder_checker,
        )
        .unwrap();

        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);

        // User computes a pseudonym
        let token = person.compute_presentation_token(params.clone()).unwrap();

        // User constructs a checker for their predicate
        let users_checker = PseudonymousShowChecker {
            token: token.clone(),
            params: params.clone(),
        };

        // Prove the predicate
        let proof = prove_birth(&mut rng, &pk, users_checker, person.clone()).unwrap();

        // Now verify the predicate
        // Make the checker with only the public data
        let verifiers_checker = PseudonymousShowChecker { token, params };
        let person_com = person.commit();
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &verifiers_checker, &person_com).unwrap());
    }
}
