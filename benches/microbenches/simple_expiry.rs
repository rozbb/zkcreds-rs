use crate::microbenches::monolithic_proof::{
    gen_monolithic_crs, prove_monolithic, verify_monolithic,
};

use core::borrow::Borrow;

use zeronym::{
    attrs::{Attrs, AttrsVar},
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    pred::{gen_pred_crs, prove_pred, PredicateChecker},
    ComNonce, ComNonceVar, ComParam, ComParamVar,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    commitment::CommitmentScheme,
    crh::{bowe_hopwood, pedersen, TwoToOneCRH},
};
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
use criterion::Criterion;
use lazy_static::lazy_static;
use linkg16::groth16;

const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 10;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

type E = Bls12_381;
type Fr = <E as PairingEngine>::Fr;

type CompressedPedersenCom<W> = zeronym::compressed_pedersen::Commitment<EdwardsParameters, W>;
type CompressedPedersenComG<W> =
    zeronym::compressed_pedersen::constraints::CommGadget<EdwardsParameters, FqVar, W>;

#[derive(Clone)]
struct Window9x63;
impl pedersen::Window for Window9x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 9;
}
type TreeH = bowe_hopwood::CRH<EdwardsParameters, Window9x63>;
type TreeHG = bowe_hopwood::constraints::CRHGadget<EdwardsParameters, FqVar>;

#[derive(Clone)]
struct CustomWindow;
impl pedersen::Window for CustomWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 2;
}

type ComScheme = CompressedPedersenCom<CustomWindow>;
type ComSchemeG = CompressedPedersenComG<CustomWindow>;

lazy_static! {
    static ref COM_PARAM: <ComScheme as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        ComScheme::setup(&mut rng).unwrap()
    };
    static ref MERKLE_CRH_PARAM: <TreeH as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <TreeH as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}

#[derive(Clone, Default)]
struct ExpiryAttrs {
    nonce: ComNonce<ComScheme>,
    expiry: Fr,
}

#[derive(Clone)]
struct ExpiryAttrsVar {
    nonce: ComNonceVar<ComScheme, ComSchemeG, Fr>,
    expiry: FpVar<Fr>,
}

impl ExpiryAttrs {
    fn new<R: Rng>(rng: &mut R, expiry: u32) -> ExpiryAttrs {
        let nonce = <ComScheme as CommitmentScheme>::Randomness::rand(rng);
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
        &*COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce<ComScheme> {
        &self.nonce
    }
}

impl ToBytesGadget<Fr> for ExpiryAttrsVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        self.expiry.to_bytes()
    }
}

impl AllocVar<ExpiryAttrs, Fr> for ExpiryAttrsVar {
    fn new_variable<T: Borrow<ExpiryAttrs>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_attrs = f();

        let default_info = ExpiryAttrs::default();

        // Unpack the given attributes
        let ExpiryAttrs {
            ref nonce,
            ref expiry,
        } = native_attrs
            .as_ref()
            .map(Borrow::borrow)
            .unwrap_or(&default_info);

        let nonce = ComNonceVar::<ComScheme, ComSchemeG, Fr>::new_variable(
            ns!(cs, "nonce"),
            || Ok(nonce),
            mode,
        )?;
        let expiry = FpVar::<Fr>::new_variable(ns!(cs, "expiry"), || Ok(*expiry), mode)?;

        Ok(ExpiryAttrsVar { nonce, expiry })
    }
}

impl AttrsVar<Fr, ExpiryAttrs, ComScheme, ComSchemeG> for ExpiryAttrsVar {
    fn get_com_param(&self) -> Result<ComParamVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        let cs = self.nonce.cs();
        ComParamVar::<_, ComSchemeG, _>::new_constant(cs, &*COM_PARAM)
    }

    fn get_com_nonce(&self) -> Result<ComNonceVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        Ok(self.nonce.clone())
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
        MERKLE_CRH_PARAM.clone(),
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
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let auth_path = tree.insert(0, &cred);
    c.bench_function("Expiry: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(&mut rng, &tree_pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        })
    });
    let tree_proof = auth_path
        .prove_membership(&mut rng, &tree_pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap();

    // Create forest proof
    let root = tree.root();
    let mut roots = ComForestRoots::new(NUM_TREES - 1);
    roots.roots.push(root);
    c.bench_function("Expiry: proving forest", |b| {
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
    c.bench_function("Expiry: proving expiry", |b| {
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

    let monolithic_pk: groth16::ProvingKey<E> = gen_monolithic_crs::<
        _,
        E,
        ExpiryAttrs,
        ExpiryAttrsVar,
        ComScheme,
        ComSchemeG,
        TreeH,
        TreeHG,
        _,
    >(
        &mut rng,
        MERKLE_CRH_PARAM.clone(),
        TREE_HEIGHT,
        NUM_TREES,
        expiry_checker.clone(),
    )
    .unwrap();
    let monolithic_vk = monolithic_pk.verifying_key();
    c.bench_function("Expiry show: proving monolithic", |b| {
        b.iter(|| {
            prove_monolithic::<_, _, _, ExpiryAttrsVar, _, ComSchemeG, _, TreeHG, _>(
                &mut rng,
                &monolithic_pk,
                &*MERKLE_CRH_PARAM,
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
        &*MERKLE_CRH_PARAM,
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
        com_forest_roots: roots,
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
    c.bench_function("Expiry: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let link_proof = link_proofs(&mut rng, &link_ctx);

    c.bench_function("Expiry: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });
}
