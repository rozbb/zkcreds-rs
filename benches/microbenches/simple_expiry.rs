use crate::microbenches::monolithic_proof::{
    gen_monolithic_crs, prove_monolithic, verify_monolithic,
};

use core::borrow::Borrow;

use zkcreds::{
    attrs::{
        AccountableAttrs as AccountableAttrsTrait, AccountableAttrsVar as AccountableAttrsVarTrait,
        Attrs, AttrsVar,
    },
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    poseidon_utils::{setup_poseidon_params, Bls12PoseidonCommitter, Bls12PoseidonCrh, ComNonce},
    pred::PredicateChecker,
    pred::{gen_pred_crs, prove_pred},
    revealing_multishow::{MultishowableAttrs, RevealingMultishowChecker},
    zk_utils::UnitVar,
    ComNonceVar, ComParam, ComParamVar,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{commitment::CommitmentScheme, crh::TwoToOneCRH};
use ark_ec::PairingEngine;
use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsParameters};
use ark_ff::{to_bytes, UniformRand};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::{
    io::Write,
    rand::{rngs::StdRng, Rng, SeedableRng},
};
use arkworks_utils::Curve;
use criterion::Criterion;
use lazy_static::lazy_static;
use linkg16::groth16;

const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

type E = Bls12_381;
type Fr = <E as PairingEngine>::Fr;

type ComScheme = Bls12PoseidonCommitter;
type ComSchemeG = Bls12PoseidonCommitter;
type TreeH = Bls12PoseidonCrh;
type TreeHG = Bls12PoseidonCrh;

#[derive(Clone, Default)]
struct ExpiryAttrs {
    nonce: ComNonce,
    expiry: Fr,
}

#[derive(Clone)]
struct ExpiryAttrsVar {
    nonce: ComNonce,
    expiry: FpVar<Fr>,
}

impl ExpiryAttrs {
    fn new<R: Rng>(rng: &mut R, expiry: u32) -> ExpiryAttrs {
        let nonce = ComNonce::rand(rng);
        ExpiryAttrs {
            nonce,
            expiry: Fr::from(expiry),
        }
    }
}

impl Attrs<Fr, ComScheme> for ExpiryAttrs {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes![self.expiry].unwrap()
    }

    fn get_com_param(&self) -> &ComParam<ComScheme> {
        &()
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl ToBytesGadget<Fr> for ExpiryAttrsVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        self.expiry.to_bytes()
    }
}

impl AttrsVar<Fr, ExpiryAttrs, ComScheme, ComSchemeG> for ExpiryAttrsVar {
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.expiry.cs()
    }

    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        attrs: &ExpiryAttrs,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let nonce = attrs.nonce.clone();
        let expiry = FpVar::<Fr>::new_witness(ns!(cs, "expiry"), || Ok(attrs.expiry))?;

        Ok(ExpiryAttrsVar { nonce, expiry })
    }

    fn get_com_param(&self) -> Result<ComParamVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        Ok(UnitVar::default())
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

#[derive(Clone, Default)]
pub(crate) struct ExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, ExpiryAttrs, ExpiryAttrsVar, ComScheme, ComSchemeG> for ExpiryChecker {
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &ExpiryAttrsVar,
    ) -> Result<(), SynthesisError> {
        // Assert that attrs.expiry > threshold_expiry
        let threshold_expiry =
            FpVar::<Fr>::new_input(ns!(cs, "threshold expiry"), || Ok(self.threshold_expiry))?;
        attrs
            .expiry
            .enforce_cmp(&threshold_expiry, core::cmp::Ordering::Greater, false)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}

// This benchmarks the linkage functions as the number of predicates increases
pub fn bench_expiry(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    let expiry_checker = ExpiryChecker {
        threshold_expiry: Fr::from(110),
    };

    // Generate CRSs
    let expiry_pk =
        gen_pred_crs::<_, _, E, _, _, _, _, TreeH, TreeHG>(&mut rng, expiry_checker.clone())
            .unwrap();
    let expiry_vk = expiry_pk.prepare_verifying_key();
    let tree_pk = gen_tree_memb_crs::<_, E, ExpiryAttrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng,
        (),
        TREE_HEIGHT,
    )
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();
    let forest_pk = gen_forest_memb_crs::<_, E, ExpiryAttrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng, NUM_TREES,
    )
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    // Make the empty attribute
    let attrs = ExpiryAttrs::new(&mut rng, 200);
    let cred = attrs.commit();

    // Create the tree proof
    let mut tree = ComTree::empty((), TREE_HEIGHT);
    let auth_path = tree.insert(0, &cred);
    c.bench_function("Expiry show: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(&mut rng, &tree_pk, &(), cred)
                .unwrap()
        })
    });
    let tree_proof = auth_path
        .prove_membership(&mut rng, &tree_pk, &(), cred)
        .unwrap();

    // Create forest proof
    let root = tree.root();
    let mut roots = ComForestRoots::new(NUM_TREES - 1);
    roots.roots.push(root);
    c.bench_function("Expiry show: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(&mut rng, &forest_pk, root, cred)
                .unwrap()
        })
    });
    let forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, root, cred)
        .unwrap();

    // Create expiry proof
    c.bench_function("Expiry show: proving expiry", |b| {
        b.iter(|| {
            prove_pred(
                &mut rng,
                &expiry_pk,
                expiry_checker.clone(),
                attrs.clone(),
                &auth_path,
            )
            .unwrap()
        })
    });
    let expiry_proof = prove_pred(
        &mut rng,
        &expiry_pk,
        expiry_checker.clone(),
        attrs.clone(),
        &auth_path,
    )
    .unwrap();

    let monolithic_pk: groth16::ProvingKey<E> =
        gen_monolithic_crs::<
            _,
            E,
            ExpiryAttrs,
            ExpiryAttrsVar,
            ComScheme,
            ComSchemeG,
            TreeH,
            TreeHG,
            _,
        >(&mut rng, (), TREE_HEIGHT, NUM_TREES, expiry_checker.clone())
        .unwrap();
    let monolithic_vk = monolithic_pk.verifying_key();
    c.bench_function("Expiry show: proving monolithic", |b| {
        b.iter(|| {
            prove_monolithic::<_, _, _, ExpiryAttrsVar, _, ComSchemeG, _, TreeHG, _>(
                &mut rng,
                &monolithic_pk,
                &(),
                &roots,
                &auth_path,
                attrs.clone(),
                expiry_checker.clone(),
            )
            .unwrap()
        })
    });
    let proof = prove_monolithic::<_, _, _, ExpiryAttrsVar, _, ComSchemeG, _, TreeHG, _>(
        &mut rng,
        &monolithic_pk,
        &(),
        &roots,
        &auth_path,
        attrs.clone(),
        expiry_checker.clone(),
    )
    .unwrap();
    c.bench_function("Expiry show: verifying monolithic", |b| {
        b.iter(|| {
            assert!(
                verify_monolithic::<_, ExpiryAttrs, ExpiryAttrsVar, _, _, _, TreeHG, _>(
                    &monolithic_vk,
                    &roots,
                    &proof,
                    expiry_checker.clone()
                )
                .unwrap()
            )
        })
    });

    // Prepare expiry inputs
    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&expiry_vk, &expiry_checker);

    let link_vk = LinkVerifyingKey::<_, _, ExpiryAttrsVar, _, _, _, _> {
        pred_inputs,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk,
        tree_verif_key: tree_vk,
        pred_verif_keys: vec![expiry_vk],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: root,
        forest_proof,
        tree_proof,
        pred_proofs: vec![expiry_proof],
        vk: link_vk.clone(),
    };
    c.bench_function("Expiry show: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let link_proof = link_proofs(&mut rng, &link_ctx);
    crate::util::record_size("Expiry", &link_proof);

    c.bench_function("Expiry show: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });
}
