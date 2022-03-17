use crate::{
    attrs::{Attrs, AttrsVar},
    pred::PredicateChecker,
};

use core::{cmp::Ordering, marker::PhantomData};

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{CRHGadget, CRH as CRHTrait},
    Error as ArkError,
};
use ark_ff::{to_bytes, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::AllocVar, bits::ToBytesGadget, eq::EqGadget, fields::fp::FpVar, uint8::UInt8,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use arkworks_gadgets::poseidon::{
    constraints::{CRHGadget as PoseidonGadget, PoseidonParametersVar},
    PoseidonParameters, Rounds as PoseidonRounds, CRH as PoseidonCRH,
};

// Domain separators for all our uses of Poseidon
const PRF1_DOMAIN_SEP: u8 = 123;
const PRF2_DOMAIN_SEP: u8 = 124;
const HASH_DOMAIN_SEP: u8 = 125;

/// An `Attrs` trait that has something that identifies the user as well as  a random seed we can
/// use for rate limiting
pub trait AccountableAttrs<ConstraintF, AC>: Attrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    fn get_id(&self) -> ConstraintF;
    fn get_seed(&self) -> ConstraintF;

    /// Computes the presentation token from the given accountable attribute
    fn compute_presentation_token<P: PoseidonRounds>(
        &self,
        params: &PoseidonParameters<ConstraintF>,
        ctr: u16,
        nonce: ConstraintF,
    ) -> Result<PresentationToken<ConstraintF>, ArkError> {
        let id = self.get_id();
        let seed = self.get_seed();

        // hidden_ctr = PRFₛ(ctr)
        let hidden_ctr: ConstraintF = {
            let hash_input = to_bytes![PRF1_DOMAIN_SEP, seed, ctr]?;

            PoseidonCRH::<_, P>::evaluate(params, &hash_input)?
        };

        // hidden_line_point = ID + H(nonce)·PRFₛ'(ctr)
        let hidden_line_point = {
            // First hash the nonce
            let nonce_hash = {
                let hash_input = to_bytes![HASH_DOMAIN_SEP, nonce]?;
                PoseidonCRH::<_, P>::evaluate(params, &hash_input)?
            };

            // Now compute PRFₛ'(ctr)
            let prf_value = {
                let hash_input = to_bytes![PRF2_DOMAIN_SEP, seed, ctr]?;
                PoseidonCRH::<_, P>::evaluate(params, &hash_input)?
            };

            // Now put it together
            id + nonce_hash * prf_value
        };

        Ok(PresentationToken {
            hidden_ctr,
            hidden_line_point,
        })
    }
}

/// The gadget version of `AccountableAttrs`
pub trait AccountableAttrsVar<ConstraintF, A, AC, ACG>: AttrsVar<ConstraintF, A, AC, ACG>
where
    ConstraintF: PrimeField,
    A: Attrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    fn get_id(&self) -> Result<FpVar<ConstraintF>, SynthesisError>;
    fn get_seed(&self) -> Result<FpVar<ConstraintF>, SynthesisError>;

    /// Computes the presentation token from the given accountable attribute
    fn compute_presentation_token<P: PoseidonRounds>(
        &self,
        params: &PoseidonParametersVar<ConstraintF>,
        ctr: &FpVar<ConstraintF>,
        nonce: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError> {
        let id = self.get_id()?;
        let seed = self.get_seed()?;

        // hidden_ctr = PRFₛ(ctr)
        let hidden_ctr = {
            let hash_input = [
                vec![UInt8::constant(PRF1_DOMAIN_SEP)],
                seed.to_bytes()?,
                ctr.to_bytes()?,
            ]
            .concat();

            PoseidonGadget::<ConstraintF, P>::evaluate(params, &hash_input)?
        };

        // hidden_line_point = ID + H(nonce)·PRFₛ'(ctr)
        let hidden_line_point = {
            // First hash the nonce
            let nonce_hash = {
                let hash_input =
                    [vec![UInt8::constant(HASH_DOMAIN_SEP)], nonce.to_bytes()?].concat();
                PoseidonGadget::<ConstraintF, P>::evaluate(params, &hash_input)?
            };

            // Now compute PRFₛ'(ctr)
            let prf_value = {
                let hash_input = [
                    vec![UInt8::constant(PRF2_DOMAIN_SEP)],
                    seed.to_bytes()?,
                    ctr.to_bytes()?,
                ]
                .concat();
                PoseidonGadget::<ConstraintF, P>::evaluate(params, &hash_input)?
            };

            // Now put it together
            id + nonce_hash * prf_value
        };

        Ok(PresentationTokenVar {
            hidden_ctr,
            hidden_line_point,
        })
    }
}

/// A pseudorandom pair of field elements. If there are ever two tokens with the same `hidden_ctr`,
/// they can be combined to derive the user's ID.
#[derive(Clone)]
pub struct PresentationToken<ConstraintF: PrimeField> {
    /// This is `PRFₛ(ctr)` where s is the seed
    hidden_ctr: ConstraintF,

    /// This is `ID + H(n)·PRFₛ'(ctr)` where `ID` is the user ID, s is the seed, and n is the
    /// presentation nonce. Notice that if `ctr` repeats then we have two elements on the line `ID
    /// + x·PRFₛ'(ctr)`. An observer can solve for the y-intercept and recover `ID`.
    hidden_line_point: ConstraintF,
}

/// The variable version of presentation token
#[derive(Clone)]
pub struct PresentationTokenVar<ConstraintF: PrimeField> {
    hidden_ctr: FpVar<ConstraintF>,
    hidden_line_point: FpVar<ConstraintF>,
}

/// Proves that `token` is the result of a PRF computation using the verifier-provided nonce and
/// the attribute's ID and random seed
#[derive(Clone)]
pub struct MultishowChecker<ConstraintF, P>
where
    ConstraintF: PrimeField,
    P: PoseidonRounds,
{
    // Public inputs //
    /// The psuedorandom values associated with this presentation
    token: PresentationToken<ConstraintF>,
    // The nonce provided by the server
    nonce: ConstraintF,
    /// Number of times this attrribute string can be shown
    max_num_presentations: u16,

    // Private inputs //
    /// The counter representing the number of times this attribute string has been shown so far
    /// (begins at 0)
    ctr: u16,

    // Constants //
    /// Poseidon parameters
    params: PoseidonParameters<ConstraintF>,
    _rounds: PhantomData<P>,
}

impl<ConstraintF, A, AV, AC, ACG, P> PredicateChecker<ConstraintF, A, AV, AC, ACG>
    for MultishowChecker<ConstraintF, P>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AV: AccountableAttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
    P: PoseidonRounds,
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
        let computed_token = attrs.compute_presentation_token::<P>(&params, &ctr, &nonce)?;

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

/*
#[cfg(test)]
mod test {
    use super::*;

    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use arkworks_gadgets::setup::common::{
        setup_params_x5_5 as setup_params, Curve, PoseidonRounds_x5_3 as PoseidonRounds,
    };

    #[test]
    fn test_show_attrs() {
        let mut rng = ark_std::test_rng();

        let params = setup_params::<Fr>(Curve::Bls381);
        let attrs = AttrString::gen(&mut rng);
        let counter = 1u16;
        let max_num_presentations = 128u16;

        let presentation_nonce =
            compute_presentation_nonce::<_, PoseidonRounds>(&params, &attrs, counter).unwrap();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MultishowCircuit::<_, PoseidonRounds>::new(
            presentation_nonce,
            attrs,
            counter,
            max_num_presentations,
            params,
        );
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("multishow circuit is {} constraints", cs.num_constraints());
        println!(
            "multishow circuit nonce is {} bytes",
            ark_ff::to_bytes![presentation_nonce].unwrap().len()
        );
        assert!(cs.is_satisfied().unwrap());
    }
}
*/
