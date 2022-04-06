use core::borrow::Borrow;

use zeronym::{
    attrs::{Attrs, AttrsVar},
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    ComNonce, ComNonceVar, ComParam, ComParamVar,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    commitment::CommitmentScheme,
    crh::{bowe_hopwood, pedersen, TwoToOneCRH},
};
use ark_ec::PairingEngine;
use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsParameters};
use ark_ff::UniformRand;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
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
use criterion::Criterion;
use lazy_static::lazy_static;

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
    const NUM_WINDOWS: usize = 0;
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
struct EmptyAttrs {
    nonce: ComNonce<ComScheme>,
}

#[derive(Clone)]
struct EmptyAttrsVar {
    nonce: ComNonceVar<ComScheme, ComSchemeG, Fr>,
}

impl EmptyAttrs {
    fn new<R: Rng>(rng: &mut R) -> EmptyAttrs {
        let nonce = <ComScheme as CommitmentScheme>::Randomness::rand(rng);
        EmptyAttrs { nonce }
    }
}

impl Attrs<Fr, ComScheme> for EmptyAttrs {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    fn get_com_param(&self) -> &ComParam<ComScheme> {
        &*COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce<ComScheme> {
        &self.nonce
    }
}

impl ToBytesGadget<Fr> for EmptyAttrsVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok(Vec::new())
    }
}

impl AllocVar<EmptyAttrs, Fr> for EmptyAttrsVar {
    fn new_variable<T: Borrow<EmptyAttrs>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_attr = f().unwrap();
        let native_attr = native_attr.borrow();

        let nonce = ComNonceVar::<ComScheme, ComSchemeG, Fr>::new_variable(
            ns!(cs, "nonce"),
            || Ok(&native_attr.nonce),
            mode,
        )?;

        Ok(EmptyAttrsVar { nonce })
    }
}

impl AttrsVar<Fr, EmptyAttrs, ComScheme, ComSchemeG> for EmptyAttrsVar {
    fn get_com_param(&self) -> Result<ComParamVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        let cs = self.nonce.cs();
        ComParamVar::<_, ComSchemeG, _>::new_constant(cs, &*COM_PARAM)
    }

    fn get_com_nonce(&self) -> Result<ComNonceVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        Ok(self.nonce.clone())
    }
}

// Record DESC,SIZE in the CSV file
const SIZE_LOG_FILE: &str = "proof_sizes.csv";
pub fn record_size(desc: impl AsRef<str>, val: &impl ark_serialize::CanonicalSerialize) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(SIZE_LOG_FILE)
        .unwrap();
    let size = val.serialized_size();
    writeln!(f, "{},{}", desc.as_ref(), size).unwrap();
}

// This benchmarks the linkage functions as the number of predicates increases
pub fn bench_empty(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // Generate CRSs
    let tree_pk = gen_tree_memb_crs::<_, E, EmptyAttrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng,
        MERKLE_CRH_PARAM.clone(),
        TREE_HEIGHT,
    )
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();
    let forest_pk = gen_forest_memb_crs::<_, E, EmptyAttrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng, NUM_TREES,
    )
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    // Make the empty attribute
    let attrs = EmptyAttrs::new(&mut rng);
    let cred = attrs.commit();

    // Create the tree proof
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let auth_path = tree.insert(0, &cred);
    c.bench_function("Empty: proving tree", |b| {
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
    c.bench_function("Empty: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(&mut rng, &forest_pk, root, cred)
                .unwrap()
        })
    });
    let forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, root, cred)
        .unwrap();

    let link_vk = LinkVerifyingKey::<_, _, EmptyAttrsVar, _, _, _, _> {
        pred_inputs: PredPublicInputs::default(),
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk,
        tree_verif_key: tree_vk,
        pred_verif_keys: Vec::new(),
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: root,
        forest_proof,
        tree_proof,
        pred_proofs: vec![],
        vk: link_vk.clone(),
    };
    c.bench_function("Empty: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let link_proof = link_proofs(&mut rng, &link_ctx);
    record_size("Empty", &link_proof);

    c.bench_function("Empty: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });
}
