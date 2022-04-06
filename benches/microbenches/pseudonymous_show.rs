use crate::microbenches::monolithic_proof::{
    gen_monolithic_crs, prove_monolithic, verify_monolithic,
};

use core::borrow::Borrow;

use zeronym::{
    attrs::{
        AccountableAttrs as AccountableAttrsTrait, AccountableAttrsVar as AccountableAttrsVarTrait,
        Attrs as AttrsTrait, AttrsVar as AttrsVarTrait,
    },
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    pred::{gen_pred_crs, prove_pred},
    pseudonymous_show::{PseudonymousAttrs, PseudonymousShowChecker},
    utils::setup_poseidon_params,
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
    r1cs::{Namespace, SynthesisError},
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
const LOG2_NUM_TREES: u32 = 10;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);
const POSEIDON_WIDTH: u8 = 5;

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
    const NUM_WINDOWS: usize = 3;
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
struct Attrs {
    nonce: ComNonce<ComScheme>,
    seed: Fr,
}

#[derive(Clone)]
struct AttrsVar {
    nonce: ComNonceVar<ComScheme, ComSchemeG, Fr>,
    seed: FpVar<Fr>,
}

impl Attrs {
    fn new<R: Rng>(rng: &mut R) -> Attrs {
        let nonce = <ComScheme as CommitmentScheme>::Randomness::rand(rng);
        let seed = Fr::rand(rng);
        Attrs { nonce, seed }
    }
}

impl AttrsTrait<Fr, ComScheme> for Attrs {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes![self.seed].unwrap()
    }

    fn get_com_param(&self) -> &ComParam<ComScheme> {
        &*COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce<ComScheme> {
        &self.nonce
    }
}

impl AccountableAttrsTrait<Fr, ComScheme> for Attrs {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Self::Id {
        Vec::new()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for AttrsVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        self.seed.to_bytes()
    }
}

impl AllocVar<Attrs, Fr> for AttrsVar {
    fn new_variable<T: Borrow<Attrs>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_attrs = f();

        let default_info = Attrs::default();

        // Unpack the given attributes
        let Attrs {
            ref nonce,
            ref seed,
        } = native_attrs
            .as_ref()
            .map(Borrow::borrow)
            .unwrap_or(&default_info);

        let nonce = ComNonceVar::<ComScheme, ComSchemeG, Fr>::new_variable(
            ns!(cs, "nonce"),
            || Ok(nonce),
            mode,
        )?;
        let seed = FpVar::<Fr>::new_variable(ns!(cs, "seed"), || Ok(*seed), mode)?;

        Ok(AttrsVar { nonce, seed })
    }
}

impl AttrsVarTrait<Fr, Attrs, ComScheme, ComSchemeG> for AttrsVar {
    fn get_com_param(&self) -> Result<ComParamVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        let cs = self.nonce.cs();
        ComParamVar::<_, ComSchemeG, _>::new_constant(cs, &*COM_PARAM)
    }

    fn get_com_nonce(&self) -> Result<ComNonceVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        Ok(self.nonce.clone())
    }
}

impl AccountableAttrsVarTrait<Fr, Attrs, ComScheme, ComSchemeG> for AttrsVar {
    type Id = Vec<UInt8<Fr>>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Self::Id, SynthesisError> {
        Ok(Vec::new())
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}

// This benchmarks the linkage functions as the number of predicates increases
pub fn bench_pseudonymous_show(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    //
    // Generate CRSs
    //

    let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
    let placeholder_checker = PseudonymousShowChecker {
        params: params.clone(),
        ..Default::default()
    };
    let pseudonymous_show_pk =
        gen_pred_crs::<_, _, E, _, _, _, _, TreeH, TreeHG>(&mut rng, placeholder_checker).unwrap();
    let pseudonymous_show_vk = pseudonymous_show_pk.prepare_verifying_key();
    let tree_pk = gen_tree_memb_crs::<_, E, Attrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng,
        MERKLE_CRH_PARAM.clone(),
        TREE_HEIGHT,
    )
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();
    let forest_pk = gen_forest_memb_crs::<_, E, Attrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng, NUM_TREES,
    )
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    //
    // User makes a cred and computes the pseudonym
    //

    let attrs = Attrs::new(&mut rng);
    let cred = attrs.commit();
    let token = attrs.compute_presentation_token(params.clone()).unwrap();

    // Create the tree proof
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let auth_path = tree.insert(0, &cred);
    c.bench_function("Pseudonymous show: proving tree", |b| {
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
    c.bench_function("Pseudonymous show: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(&mut rng, &forest_pk, root, cred)
                .unwrap()
        })
    });
    let forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, root, cred)
        .unwrap();

    // Create pseudonym proof
    let pseudonymous_show_checker = PseudonymousShowChecker { token, params };
    c.bench_function("Pseudonymous show: proving pseudonym", |b| {
        b.iter(|| {
            prove_pred(
                &mut rng,
                &pseudonymous_show_pk,
                pseudonymous_show_checker.clone(),
                attrs.clone(),
                &auth_path,
            )
            .unwrap()
        })
    });
    let pseudonymous_show_proof = prove_pred(
        &mut rng,
        &pseudonymous_show_pk,
        pseudonymous_show_checker.clone(),
        attrs.clone(),
        &auth_path,
    )
    .unwrap();

    let monolithic_pk: groth16::ProvingKey<E> =
        gen_monolithic_crs::<_, E, Attrs, AttrsVar, ComScheme, ComSchemeG, TreeH, TreeHG, _>(
            &mut rng,
            MERKLE_CRH_PARAM.clone(),
            TREE_HEIGHT,
            NUM_TREES,
            pseudonymous_show_checker.clone(),
        )
        .unwrap();
    let monolithic_vk = monolithic_pk.verifying_key();
    c.bench_function("Psuedonymous show: proving monolithic", |b| {
        b.iter(|| {
            prove_monolithic::<_, _, _, AttrsVar, _, ComSchemeG, _, TreeHG, _>(
                &mut rng,
                &monolithic_pk,
                &*MERKLE_CRH_PARAM,
                &roots,
                &auth_path,
                attrs.clone(),
                pseudonymous_show_checker.clone(),
            )
            .unwrap()
        })
    });
    let proof = prove_monolithic::<_, _, _, AttrsVar, _, ComSchemeG, _, TreeHG, _>(
        &mut rng,
        &monolithic_pk,
        &*MERKLE_CRH_PARAM,
        &roots,
        &auth_path,
        attrs.clone(),
        pseudonymous_show_checker.clone(),
    )
    .unwrap();
    c.bench_function("Pseudonymous show: verifying monolithic", |b| {
        b.iter(|| {
            assert!(verify_monolithic::<_, Attrs, AttrsVar, _, _, _, TreeHG, _>(
                &monolithic_vk,
                &roots,
                &proof,
                pseudonymous_show_checker.clone()
            )
            .unwrap())
        })
    });

    // Prepare expiry inputs
    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&pseudonymous_show_vk, &pseudonymous_show_checker);

    let link_vk = LinkVerifyingKey::<_, _, AttrsVar, _, _, _, _> {
        pred_inputs,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk,
        tree_verif_key: tree_vk,
        pred_verif_keys: vec![pseudonymous_show_vk],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: root,
        forest_proof,
        tree_proof,
        pred_proofs: vec![pseudonymous_show_proof],
        vk: link_vk.clone(),
    };
    c.bench_function("Pseudonymous show: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let link_proof = link_proofs(&mut rng, &link_ctx);

    c.bench_function("Pseudonymous show: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });
}
