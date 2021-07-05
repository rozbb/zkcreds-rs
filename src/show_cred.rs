use core::{cmp::Ordering, marker::PhantomData};

use ark_crypto_primitives::crh::constraints::CRHGadget;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, bits::ToBytesGadget, eq::EqGadget, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use arkworks_gadgets::poseidon::{
    constraints::{CRHGadget as PoseidonGadget, PoseidonParametersVar},
    PoseidonParameters, Rounds as PoseidonRounds, CRH as PoseidonCRH,
};

/// A credential is a 128 bit bitstring
struct Credential([u8; 16]);

pub struct NShowCircuit<ConstraintF, P>
where
    ConstraintF: PrimeField,
    P: PoseidonRounds,
{
    // Public inputs //
    /// The nonce associated to this presentation
    presentation_nonce: ConstraintF,

    // Private inputs //
    /// The user's credential
    cred: Option<Credential>,
    /// The counter representing the number of times this credential has been shown so far (begins
    /// at 0)
    counter: Option<u16>,

    // Constants //
    /// Number of times this credential can be shown
    n: u16,
    /// Poseidon parameters
    params: PoseidonParameters<ConstraintF>,
    _rounds: PhantomData<P>,
}

impl<ConstraintF, P> ConstraintSynthesizer<ConstraintF> for NShowCircuit<ConstraintF, P>
where
    ConstraintF: PrimeField,
    P: PoseidonRounds,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Witness Poseidon and counter bound constants
        let params_var = PoseidonParametersVar::new_constant(ns!(cs, "prf param"), &self.params)?;
        let n_var = {
            // Convert the u16 to a field element first. Then witness it.
            let n: ConstraintF = self.n.into();
            FpVar::new_constant(ns!(cs, "n param"), &n)?
        };

        // Witness the nonce, credential, and counter
        let presentation_nonce_var = FpVar::<ConstraintF>::new_input(
            ns!(cs, "nonce input"),
            || Ok(self.presentation_nonce),
        )?;
        // Convert the credential bytes to a field element
        let cred_var = FpVar::<ConstraintF>::new_witness(ns!(cs, "cred wit"), || {
            self.cred
                .as_ref()
                .map(|c| ConstraintF::from_be_bytes_mod_order(&c.0))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let counter_var = {
            // Convert the u16 to a field element first. Then witness it
            let counter: Option<ConstraintF> = self.counter.as_ref().map(|&c| c.into());
            FpVar::<ConstraintF>::new_witness(ns!(cs, "counter wit"), || {
                counter.ok_or(SynthesisError::AssignmentMissing)
            })?
        };
        /*
        let counter_var = UInt16::new_witness(ns!(cs, "counter wit"), || {
            self.counter.0.ok_or(SynthesisError::AssignmentMissing)
        })?;
        */

        // Assert that counter < n
        counter_var.enforce_cmp(&n_var, Ordering::Less, false)?;

        // Finally, assert presentation_nonce == H(cred, counter)
        let hash = {
            let cred_bytes = cred_var.to_bytes()?;
            let counter_bytes = counter_var.to_bytes()?;
            let hash_input = &[cred_bytes, counter_bytes].concat();

            PoseidonGadget::<ConstraintF, P>::evaluate(&params_var, &hash_input)?
        };
        hash.enforce_equal(&presentation_nonce_var)
    }
}
