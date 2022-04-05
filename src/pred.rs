use crate::{
    attrs::{Attrs, AttrsVar},
    com_tree::ComTreePath,
    proof_data_structures::{PredProof, PredProvingKey, PredPublicInput, PredVerifyingKey},
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;
use linkg16::groth16;

/// Describes any predicate that someone might want to prove over an `Attrs` object.
pub trait PredicateChecker<ConstraintF, A, AV, AC, ACG>
where
    ConstraintF: PrimeField,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// Enforces constraints on the given attributes
    fn pred(self, cs: ConstraintSystemRef<ConstraintF>, attrs: &AV) -> Result<(), SynthesisError>;

    /// This outputs the field elements corresponding to the public inputs of this predicate. This
    /// DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<ConstraintF>;
}

pub fn gen_pred_crs<R, P, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    checker: P,
) -> Result<PredProvingKey<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let prover: PredicateProver<_, _, _, _, _, _, _, HG> = PredicateProver {
        checker,
        attrs: A::default(),
        merkle_root: H::Output::default(),
        _marker: PhantomData,
    };
    let pk = groth16::generate_random_parameters(prover, rng)?;
    Ok(PredProvingKey {
        pk,
        _marker: PhantomData,
    })
}

/// Proves the given predicate over the attributes
pub fn prove_pred<R, P, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    pk: &PredProvingKey<E, A, AV, AC, ACG, H, HG>,
    checker: P,
    attrs: A,
    auth_path: &ComTreePath<E::Fr, H, AC>,
) -> Result<PredProof<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let merkle_root = auth_path.path.root.clone();
    let prover: PredicateProver<_, _, _, _, _, _, _, HG> = PredicateProver {
        checker,
        attrs,
        merkle_root,
        _marker: PhantomData,
    };
    let proof = groth16::create_random_proof(prover, &pk.pk, rng)?;
    Ok(PredProof {
        proof,
        _marker: PhantomData,
    })
}

/// Proves the given birth predicate over the given attribute. Same as `prove_pred` except we don't
/// care about the auth path
pub fn prove_birth<R, P, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    pk: &PredProvingKey<E, A, AV, AC, ACG, H, HG>,
    checker: P,
    attrs: A,
) -> Result<PredProof<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    // It sufficient to make a default com tree path without specifying length, since only the
    // placeholder root value is used
    let auth_path = ComTreePath::default();
    prove_pred(rng, pk, checker, attrs, &auth_path)
}

/// Verifies a predicate proof. For testing purposes only
#[doc(hidden)]
pub fn verify_pred<P, E, A, AV, AC, ACG, H, HG>(
    vk: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    proof: &PredProof<E, A, AV, AC, ACG, H, HG>,
    checker: &P,
    attrs_com: &AC::Output,
    merkle_root: &H::Output,
) -> Result<bool, SynthesisError>
where
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let attr_com_input = attrs_com.to_field_elements().unwrap();
    let root_input = merkle_root.to_field_elements().unwrap();

    let all_inputs = [attr_com_input, root_input, checker.public_inputs()].concat();
    groth16::verify_proof(&vk.vk, &proof.proof, &all_inputs)
}

// Same as a predicate proof but we don't care about the merkle root
/// Verifies a birth predicate proof
pub fn verify_birth<P, E, A, AV, AC, ACG, H, HG>(
    vk: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    proof: &PredProof<E, A, AV, AC, ACG, H, HG>,
    checker: &P,
    attrs_com: &AC::Output,
) -> Result<bool, SynthesisError>
where
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let merkle_root = H::Output::default();
    verify_pred(vk, proof, checker, attrs_com, &merkle_root)
}

pub fn prepare_pred_inputs<R, P, E, A, AV, AC, ACG, H, HG>(
    vk: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    checker: &P,
) -> Result<PredPublicInput<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let pinput = groth16::prepare_inputs(&vk.vk, &checker.public_inputs())?;
    Ok(PredPublicInput {
        pinput,
        _marker: PhantomData,
    })
}

/// Internal object for proving predicates. This needs to implement `ConstraintSynthesizer` in
/// order to pass to the Groth16 proving functions. `AC` is the attribute commitment scheme, `MC`
/// is the merkle root commitment scheme.
pub(crate) struct PredicateProver<ConstraintF, P, A, AV, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    P: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    checker: P,
    attrs: A,
    merkle_root: H::Output,
    _marker: PhantomData<(ConstraintF, AV, AC, ACG, HG)>,
}

impl<ConstraintF, P, A, AV, AC, ACG, H, HG> ConstraintSynthesizer<ConstraintF>
    for PredicateProver<ConstraintF, P, A, AV, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    P: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Witness the public variables. In ALL zeronym proofs, it's the commitment to the
        // attributes and the merkle root
        let attrs_com_var =
            ACG::OutputVar::new_input(ns!(cs, "attrs com var"), || Ok(self.attrs.commit()))?;
        let _root_var = HG::OutputVar::new_input(ns!(cs, "root var"), || Ok(self.merkle_root))?;

        // Check that the attrs commitment is consistent
        let attrs_var = AV::new_witness(ns!(cs, "attrs var"), || Ok(&self.attrs))?;
        attrs_com_var.enforce_equal(&attrs_var.commit()?)?;

        // Finally assert the predicate is true
        self.checker.pred(cs, &attrs_var)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::test_util::{AgeChecker, NameAndBirthYear, TestTreeH, TestTreeHG};

    use ark_bls12_381::{Bls12_381 as E, Fr};

    /// Tests a predicate that returns true iff the given `NameAndBirthYear` is at least 21
    #[test]
    fn test_age() {
        let mut rng = ark_std::test_rng();

        // We choose that anyone born in 2001 or earlier satisfies our predicate
        let checker = AgeChecker {
            threshold_birth_year: Fr::from(2001u16),
        };

        // Generate the predicate circuit's CRS
        let pk =
            gen_pred_crs::<_, _, E, _, _, _, _, TestTreeH, TestTreeHG>(&mut rng, checker.clone())
                .unwrap();

        // First name is UTF-8 encoded, padded at the end with null bytes
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        // Make a placeholder auth path. This value is only relevant when we start linking
        // proofs. Together. Ignore for this test.
        let auth_path = ComTreePath::default();
        let merkle_root = auth_path.path.root;

        // Prove the predicate
        let proof = prove_pred(&mut rng, &pk, checker.clone(), person.clone(), &auth_path).unwrap();

        // Ordinarily we wouldn't be able to verify a predicate proof, since it requires knowledge
        // of the attribute commitment. But this is testing mode and we know this value, so let's
        // make sure the predicate proof verifies.
        let person_com = person.commit();
        let vk = pk.prepare_verifying_key();
        assert!(verify_pred(&vk, &proof, &checker, &person_com, &merkle_root).unwrap());
    }
}
