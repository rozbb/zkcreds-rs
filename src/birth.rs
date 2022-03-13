use crate::{
    attrs::{Attrs, AttrsVar},
    pred::PredicateChecker,
    proof_data_structures::{BirthProof, BirthProvingKey, BirthPublicInput, BirthVerifyingKey},
    Com,
};

use core::marker::PhantomData;

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;

pub fn gen_birth_crs<R, C, E, A, AV, AC, ACG>(
    rng: &mut R,
    birth_checker: C,
) -> Result<BirthProvingKey<E, A, AV, AC, ACG>, SynthesisError>
where
    R: Rng,
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
{
    let prover = BirthProver {
        birth_checker,
        attrs: A::default(),
        _marker: PhantomData,
    };
    let pk = ark_groth16::generate_random_parameters(prover, rng)?;
    Ok(BirthProvingKey {
        pk,
        _marker: PhantomData,
    })
}

pub fn prove_birth<R, C, E, A, AV, AC, ACG>(
    rng: &mut R,
    pk: &BirthProvingKey<E, A, AV, AC, ACG>,
    birth_checker: C,
    attrs: A,
) -> Result<BirthProof<E, A, AV, AC, ACG>, SynthesisError>
where
    R: Rng,
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
{
    let prover = BirthProver {
        birth_checker,
        attrs,
        _marker: PhantomData,
    };
    let proof = ark_groth16::create_random_proof(prover, &pk.pk, rng)?;
    Ok(BirthProof {
        proof,
        _marker: PhantomData,
    })
}

pub fn verify_birth<C, E, A, AV, AC, ACG>(
    vk: &BirthVerifyingKey<E, A, AV, AC, ACG>,
    proof: &BirthProof<E, A, AV, AC, ACG>,
    birth_checker: &C,
    attrs_com: &Com<AC>,
) -> Result<bool, SynthesisError>
where
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
{
    let attr_com_input = attrs_com.to_field_elements().unwrap();

    let all_inputs = [attr_com_input, birth_checker.public_inputs()].concat();
    ark_groth16::verify_proof(&vk.pvk, &proof.proof, &all_inputs)
}

pub fn prepare_pred_inputs<R, C, E, A, AV, AC, ACG>(
    vk: &BirthVerifyingKey<E, A, AV, AC, ACG>,
    birth_checker: &C,
) -> Result<BirthPublicInput<E, A, AV, AC, ACG>, SynthesisError>
where
    R: Rng,
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
{
    let pinput = ark_groth16::prepare_inputs(&vk.pvk, &birth_checker.public_inputs())?;
    Ok(BirthPublicInput {
        pinput,
        _marker: PhantomData,
    })
}

/// Internal object for proving birth predicates. This needs to implement `ConstraintSynthesizer`
/// in order to pass to the Groth16 proving functions. `AC` is the attribute commitment scheme,
/// `MC` is the merkle root commitment scheme.
pub(crate) struct BirthProver<ConstraintF, C, A, AV, AC, ACG>
where
    ConstraintF: PrimeField,
    C: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    birth_checker: C,
    attrs: A,
    _marker: PhantomData<(ConstraintF, AV, AC, ACG)>,
}

impl<ConstraintF, C, A, AV, AC, ACG> ConstraintSynthesizer<ConstraintF>
    for BirthProver<ConstraintF, C, A, AV, AC, ACG>
where
    ConstraintF: PrimeField,
    C: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Witness the commitment
        let attrs_com_var =
            ACG::OutputVar::new_input(ns!(cs, "attrs com var"), || Ok(self.attrs.commit()))?;

        // Check that the attrs commitment is consistent
        let attrs_var = AV::new_witness(ns!(cs, "attrs var"), || Ok(&self.attrs))?;
        attrs_com_var.enforce_equal(&attrs_var.commit()?)?;

        // Finally assert the birth predicate is true
        self.birth_checker.pred(cs, &attrs_var)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{pred::test::AgeChecker, test_util::NameAndBirthYear};

    use ark_bls12_381::{Bls12_381 as E, Fr};

    #[test]
    fn test_birth() {
        let mut rng = ark_std::test_rng();

        // We choose that anyone born in 2001 or earlier satisfies our predicate
        let birth_checker = AgeChecker {
            threshold_birth_year: Fr::from(2001u16),
        };

        // Generate the birth circuit's CRS
        let pk = gen_birth_crs::<_, _, E, _, _, _, _>(&mut rng, birth_checker.clone()).unwrap();

        // First name is UTF-8 encoded, padded at the end with null bytes
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);

        // Prove the predicate
        let proof = prove_birth(&mut rng, &pk, birth_checker.clone(), person.clone()).unwrap();

        // Ordinarily we wouldn't be able to verify a predicate proof, since it requires knowledge
        // of the attribute commitment. But this is testing mode and we know this value, so let's
        // make sure the predicate proof verifies.
        let person_com = person.commit();
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &birth_checker, &person_com).unwrap());
    }
}
