// A horrible hack to let me use helper code from another module in benches
#[path = "microbenches/monolithic_proof.rs"]
mod monolithic_proof;
use monolithic_proof::{gen_monolithic_crs, prove_monolithic, verify_monolithic};

use core::borrow::Borrow;

use zkcreds::{
    attrs::{Attrs, AttrsVar},
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    identity_crh::UnitVar,
    link::{
        link_proofs_notree, verif_link_proof_notree, LinkProofCtx, LinkVerifyingKey,
        PredPublicInputs,
    },
    pred::PredicateChecker,
    pred::{gen_pred_crs, prove_pred},
    utils::{Bls12PoseidonCommitter, Bls12PoseidonCrh, ComNonce},
    ComParam, ComParamVar,
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
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

type E = Bls12_381;
type Fr = <E as PairingEngine>::Fr;

/*
type CompressedPedersenCom<W> =
    zkcreds::compressed_pedersen::PedersenCommitter<EdwardsParameters, W>;
type CompressedPedersenComG<W> =
    zkcreds::compressed_pedersen::constraints::CommGadget<EdwardsParameters, FqVar, W>;

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
*/

type ComScheme = Bls12PoseidonCommitter;
type ComSchemeG = Bls12PoseidonCommitter;
type TreeH = Bls12PoseidonCrh;
type TreeHG = Bls12PoseidonCrh;

lazy_static! {
    static ref COM_PARAM: <ComScheme as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        ComScheme::setup(&mut rng).unwrap()
    };
    static ref MERKLE_CRH_PARAM: <TreeH as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <TreeH as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}

#[derive(Clone, Default)]
struct EmptyAttrs {
    nonce: ComNonce,
}

#[derive(Clone)]
struct EmptyAttrsVar {
    nonce: ComNonce,
    cs: ConstraintSystemRef<Fr>,
}

impl EmptyAttrs {
    fn new<R: Rng>(rng: &mut R) -> EmptyAttrs {
        let nonce = ComNonce::rand(rng);
        EmptyAttrs { nonce }
    }
}

/// An empty predicate type. We need this for our monolithic proofs
struct EmptyPred;
impl PredicateChecker<Fr, EmptyAttrs, EmptyAttrsVar, ComScheme, ComSchemeG> for EmptyPred {
    fn pred(
        self,
        _cs: ConstraintSystemRef<Fr>,
        _attrs_com: &FpVar<Fr>,
        _attrs: &EmptyAttrsVar,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        Vec::new()
    }
}

impl Attrs<Fr, ComScheme> for EmptyAttrs {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    fn get_com_param(&self) -> &ComParam<ComScheme> {
        &()
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl ToBytesGadget<Fr> for EmptyAttrsVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok(Vec::new())
    }
}

impl AttrsVar<Fr, EmptyAttrs, ComScheme, ComSchemeG> for EmptyAttrsVar {
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.cs.clone()
    }

    fn get_com_param(&self) -> Result<ComParamVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        Ok(UnitVar::default())
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }

    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        attrs: &EmptyAttrs,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let nonce = attrs.nonce.clone();

        Ok(EmptyAttrsVar { nonce, cs })
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
    c.bench_function("Empty show: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(&mut rng, &tree_pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        })
    });
    let mut tree_proof = auth_path
        .prove_membership(&mut rng, &tree_pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap();
    tree_proof.proof = Default::default();

    // Create forest proof
    let root = tree.root();
    let mut roots = ComForestRoots::new(NUM_TREES - 1);
    roots.roots.push(root);
    c.bench_function("Empty show: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(&mut rng, &forest_pk, root, cred)
                .unwrap()
        })
    });
    let mut forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, root, cred)
        .unwrap();
    forest_proof.proof = Default::default();

    use zkcreds::sig::{SchnorrPrivkey, SchnorrPubkey, SigChecker};
    let privkey = SchnorrPrivkey::gen(&mut rng);
    let pubkey = SchnorrPubkey::from(&privkey);
    let sig = privkey.sign(&mut rng, &cred);
    let sig_checker = SigChecker {
        pubkey: pubkey.clone(),
        privkey,
        sig,
    };
    let sig_pk =
        gen_pred_crs::<_, _, E, _, _, _, _, TreeH, TreeHG>(&mut rng, sig_checker.clone()).unwrap();
    let sig_vk = sig_pk.prepare_verifying_key();
    c.bench_function("Empty show: proving sigcheck", |b| {
        b.iter(|| {
            prove_pred(
                &mut rng,
                &sig_pk,
                sig_checker.clone(),
                attrs.clone(),
                &auth_path,
            )
            .unwrap()
        })
    });
    let sig_proof = prove_pred(
        &mut rng,
        &sig_pk,
        sig_checker.clone(),
        attrs.clone(),
        &auth_path,
    )
    .unwrap();

    let monolithic_pk: groth16::ProvingKey<E> = gen_monolithic_crs::<
        _,
        E,
        EmptyAttrs,
        EmptyAttrsVar,
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
        EmptyPred,
    )
    .unwrap();
    let monolithic_vk = monolithic_pk.verifying_key();
    c.bench_function("Empty show: proving monolithic", |b| {
        b.iter(|| {
            prove_monolithic::<_, _, _, EmptyAttrsVar, _, ComSchemeG, _, TreeHG, _>(
                &mut rng,
                &monolithic_pk,
                &*MERKLE_CRH_PARAM,
                &roots,
                &auth_path,
                attrs.clone(),
                EmptyPred,
            )
            .unwrap()
        })
    });
    let proof = prove_monolithic::<_, _, _, EmptyAttrsVar, _, ComSchemeG, _, TreeHG, _>(
        &mut rng,
        &monolithic_pk,
        &*MERKLE_CRH_PARAM,
        &roots,
        &auth_path,
        attrs.clone(),
        EmptyPred,
    )
    .unwrap();
    c.bench_function("Empty show: verifying monolithic", |b| {
        b.iter(|| {
            assert!(
                verify_monolithic::<_, EmptyAttrs, EmptyAttrsVar, _, _, _, TreeHG, _>(
                    &monolithic_vk,
                    &roots,
                    &proof,
                    EmptyPred,
                )
                .unwrap()
            )
        })
    });

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&sig_vk, &sig_checker);

    let link_vk = LinkVerifyingKey::<_, _, EmptyAttrsVar, _, _, _, _> {
        pred_inputs,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk,
        tree_verif_key: tree_vk,
        pred_verif_keys: vec![sig_vk],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: root,
        forest_proof,
        tree_proof,
        pred_proofs: vec![sig_proof],
        vk: link_vk.clone(),
    };
    c.bench_function("Empty show: proving linkage", |b| {
        b.iter(|| link_proofs_notree(&mut rng, &link_ctx))
    });
    let link_proof = link_proofs_notree(&mut rng, &link_ctx);
    record_size("Empty", &link_proof);

    c.bench_function("Empty show: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof_notree(&link_proof, &link_vk).unwrap()))
    });
}
