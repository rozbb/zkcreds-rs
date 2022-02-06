use crate::common::{AttrString, AttrStringVar, ATTR_STRING_LEN};

use core::{cmp::Ordering, marker::PhantomData};
use std::io::Write;

use ark_crypto_primitives::{
    crh::{constraints::CRHGadget, CRH as CRHTrait},
    Error as ArkError,
};
use ark_ff::{to_bytes, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, bits::ToBytesGadget, eq::EqGadget, fields::fp::FpVar, R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use arkworks_gadgets::poseidon::{
    constraints::{CRHGadget as PoseidonGadget, PoseidonParametersVar},
    PoseidonParameters, Rounds as PoseidonRounds, CRH as PoseidonCRH,
};

use byteorder::{LittleEndian, WriteBytesExt};

pub struct MultishowCircuit<ConstraintF, P>
where
    ConstraintF: PrimeField,
    P: PoseidonRounds,
{
    // Public inputs //
    /// The nonce associated to this presentation
    presentation_nonce: ConstraintF,
    /// Number of times this attrribute string can be shown
    max_num_presentations: u16,

    // Private inputs //
    /// The user's attribute string
    attrs: Option<AttrString>,
    /// The counter representing the number of times this attribute string has been shown so far
    /// (begins at 0)
    counter: Option<u16>,

    // Constants //
    /// Poseidon parameters
    params: PoseidonParameters<ConstraintF>,
    _rounds: PhantomData<P>,
}

impl<ConstraintF, P> MultishowCircuit<ConstraintF, P>
where
    ConstraintF: PrimeField,
    P: PoseidonRounds,
{
    pub fn new(
        presentation_nonce: ConstraintF,
        attrs: AttrString,
        counter: u16,
        max_num_presentations: u16,
        params: PoseidonParameters<ConstraintF>,
    ) -> Self {
        MultishowCircuit {
            presentation_nonce,
            max_num_presentations,
            attrs: Some(attrs),
            counter: Some(counter),
            params,
            _rounds: PhantomData,
        }
    }
}

impl<ConstraintF, P> ConstraintSynthesizer<ConstraintF> for MultishowCircuit<ConstraintF, P>
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
        let max_num_presentations_var = {
            // Convert the u16 to a field element first. Then witness it.
            let n: ConstraintF = self.max_num_presentations.into();
            FpVar::new_input(ns!(cs, "max_num_presentations param"), || Ok(n))?
        };

        // Witness the nonce, attrs, and counter
        let presentation_nonce_var =
            FpVar::<ConstraintF>::new_input(ns!(cs, "nonce input"), || {
                Ok(&self.presentation_nonce)
            })?;
        // Convert the attribute string bytes to a field element
        let attrs_var = AttrStringVar::new_witness(ns!(cs, "attrs wit"), || {
            self.attrs.as_ref().ok_or(SynthesisError::AssignmentMissing)
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

        // Assert that counter < max_num_presentations
        counter_var.enforce_cmp(&max_num_presentations_var, Ordering::Less, false)?;

        // Finally, assert presentation_nonce == H(attrs, counter, n)
        let hash = {
            // Only use the first two bytes of the counter. This is legal because already checked
            // that counter < max_num_presentations, and n: u16 is a public input.
            let counter_bytes_var = counter_var.to_bytes()?;
            let hash_input = &[&attrs_var.to_bytes()?, &counter_bytes_var[..2]].concat();

            println!(
                "hash var input {:x?}",
                hash_input
                    .iter()
                    .map(|c| c.value())
                    .collect::<Result<Vec<u8>, _>>()
            );

            PoseidonGadget::<ConstraintF, P>::evaluate(&params_var, hash_input)?
        };
        hash.enforce_equal(&presentation_nonce_var)
    }
}

pub fn compute_presentation_nonce<F, P>(
    params: &PoseidonParameters<F>,
    attrs: &AttrString,
    counter: u16,
) -> Result<F, ArkError>
where
    F: PrimeField,
    P: PoseidonRounds,
{
    let mut hash_input = [0u8; ATTR_STRING_LEN + 2];
    let mut buf = &mut hash_input[..];

    // Presentation nonce is H(attrs, counter, n)
    buf.write_all(&to_bytes!(attrs).unwrap())
        .expect("couldn't write attrs to buf");
    buf.write_u16::<LittleEndian>(counter)
        .expect("couldn't write show counter to buf");

    PoseidonCRH::<F, P>::evaluate(params, &hash_input)
}

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
