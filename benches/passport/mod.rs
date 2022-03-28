mod ark_sha256;
mod issuance_checker;
mod params;
mod passport_dump;
mod passport_info;
mod preds;
mod sig_verif;

use crate::passport::{
    issuance_checker::{IssuanceReq, PassportHashChecker},
    params::{
        ComForest, ComForestRoots, ComTree, ComTreePath, ForestProof, ForestProvingKey,
        ForestVerifyingKey, PassportComScheme, PassportComSchemeG, PredProof, PredProvingKey,
        PredVerifyingKey, TreeProof, TreeProvingKey, TreeVerifyingKey, H, HG, MERKLE_CRH_PARAM,
        STATE_ID_LEN,
    },
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
    preds::{
        AgeAndExpiryChecker, AgeChecker, AgeFaceExpiryChecker, AgeMultishowExpiryChecker,
        ExpiryChecker, FaceChecker,
    },
    sig_verif::load_usa_pubkey,
};

use zeronym::{
    attrs::Attrs,
    link::{
        link_proofs, verif_link_proof, GsCrs, LinkProofCtx, LinkVerifyingKey, PredPublicInputs,
    },
    pred::{prove_birth, prove_pred, verify_birth, PredicateChecker},
    revealing_multishow::{MultishowableAttrs, RevealingMultishowChecker},
    utils::setup_poseidon_params,
    Com,
};

use std::fs::File;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_std::rand::{CryptoRng, Rng};
use arkworks_utils::Curve;
use criterion::Criterion;

const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 10;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

const POSEIDON_WIDTH: u8 = 5;

// Sample parameters for passport validation. All passports must expire some time after TODAY, and
// be issued by ISSUING_STATE
const TODAY: u32 = 20220101u32;
const MAX_VALID_YEARS: u32 = 10u32;
const TWENTY_ONE_YEARS_AGO: u32 = TODAY - 210000;
const ISSUING_STATE: [u8; STATE_ID_LEN] = *b"USA";

fn load_dump() -> PassportDump {
    let file = File::open("benches/passport/michaels_passport.json").unwrap();
    serde_json::from_reader(file).unwrap()
}

fn rand_tree<R: Rng>(rng: &mut R) -> ComTree {
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let idx: u16 = rng.gen();
    let leaf = Com::<PassportComScheme>::rand(rng);
    tree.insert(idx as u64, &leaf);
    tree
}

fn rand_forest<R: Rng>(rng: &mut R) -> ComForest {
    let trees = (0..NUM_TREES).map(|_| rand_tree(rng)).collect();
    ComForest { trees }
}

struct IssuerState {
    /// The forest of commitments
    com_forest: ComForest,
    /// The next free tree to insert a commitment
    next_free_tree: usize,
    /// The next free leaf in that tree to insert a commitment
    next_free_leaf: u64,
}

fn gen_issuance_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // Generate the hash checker circuit's CRS
    let pk = zeronym::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, PassportHashChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

fn gen_agefaceexpiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // Generate the hash checker circuit's CRS
    let pk = zeronym::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, AgeFaceExpiryChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

fn gen_expiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // Generate the hash checker circuit's CRS
    let pk = zeronym::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, ExpiryChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

fn gen_ageexpiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // Generate the hash checker circuit's CRS
    let pk = zeronym::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, AgeAndExpiryChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

fn gen_multishow_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    let checker = get_multishow_checker(&PersonalInfo::default());

    // Generate the hash checker circuit's CRS
    let pk = zeronym::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, checker)
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

fn gen_agemultishowexpiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // Generate the hash checker circuit's CRS
    let pk = zeronym::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(
        rng,
        get_agemultishowexpiry_checker(&PersonalInfo::default()),
    )
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

fn gen_tree_crs<R: Rng>(rng: &mut R) -> (TreeProvingKey, TreeVerifyingKey) {
    // Generate the predicate circuit's CRS
    let pk = zeronym::com_tree::gen_tree_memb_crs::<
        _,
        Bls12_381,
        PersonalInfo,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, MERKLE_CRH_PARAM.clone(), TREE_HEIGHT)
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

fn gen_forest_crs<R: Rng>(rng: &mut R) -> (ForestProvingKey, ForestVerifyingKey) {
    // Generate the predicate circuit's CRS
    let pk = zeronym::com_forest::gen_forest_memb_crs::<
        _,
        Bls12_381,
        PersonalInfo,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, NUM_TREES)
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

/// Makes a random new issuer state
fn init_issuer<R: Rng>(rng: &mut R) -> IssuerState {
    let com_forest = rand_forest(rng);
    let next_free_tree = rng.gen_range(0..NUM_TREES);
    let next_free_leaf = rng.gen_range(0..2u64.pow(TREE_HEIGHT - 1));

    IssuerState {
        com_forest,
        next_free_tree,
        next_free_leaf,
    }
}

/// With their passport, a user constructs a `PersonalInfo` struct and requests issuance
fn user_req_issuance<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    issuance_pk: &PredProvingKey,
) -> (PersonalInfo, IssuanceReq) {
    // Load the passport and parse it into a `PersonalInfo` struct
    let dump = load_dump();
    let my_info = PersonalInfo::from_passport(rng, &dump, TODAY, MAX_VALID_YEARS);
    let attrs_com = my_info.commit();

    // Make a hash checker struct using our private data
    let hash_checker =
        PassportHashChecker::from_passport(&dump, ISSUING_STATE, TODAY, MAX_VALID_YEARS);

    // Prove the passport hash is correctly computed
    c.bench_function("Passport: proving birth", |b| {
        b.iter(|| prove_birth(rng, issuance_pk, hash_checker.clone(), my_info.clone()).unwrap())
    });
    let hash_proof = prove_birth(rng, issuance_pk, hash_checker, my_info.clone()).unwrap();

    // Now put together the issuance request
    let req = IssuanceReq {
        attrs_com,
        econtent_hash: dump.econtent_hash(),
        sig: dump.sig,
        hash_proof,
    };

    (my_info, req)
}

/// An issuer takes an issuance request and validates it
fn issue(
    c: &mut Criterion,
    state: &mut IssuerState,
    birth_vk: &PredVerifyingKey,
    req: &IssuanceReq,
) -> ComTreePath {
    // Check that the hash was computed correctly and the hash's signature is correct
    let hash_checker =
        PassportHashChecker::from_issuance_req(req, ISSUING_STATE, TODAY, MAX_VALID_YEARS);
    let sig_pubkey = load_usa_pubkey();
    c.bench_function("Passport: verifying birth+sig", |b| {
        b.iter(|| {
            assert!(
                verify_birth(birth_vk, &req.hash_proof, &hash_checker, &req.attrs_com).unwrap()
            );
            assert!(sig_pubkey.verify(&req.sig, &req.econtent_hash));
        })
    });

    // Insert
    state.com_forest.trees[state.next_free_tree].insert(state.next_free_leaf, &req.attrs_com)
}

fn get_age_checker() -> AgeChecker {
    AgeChecker {
        threshold_dob: Fr::from(TWENTY_ONE_YEARS_AGO),
    }
}

fn get_expiry_checker() -> ExpiryChecker {
    ExpiryChecker {
        threshold_expiry: Fr::from(TODAY),
    }
}

fn get_face_checker(info: &PersonalInfo) -> FaceChecker {
    FaceChecker {
        face_hash: info.biometrics_hash(),
    }
}

fn get_multishow_checker(info: &PersonalInfo) -> RevealingMultishowChecker<Fr> {
    let poseidon_params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
    let max_num_presentations: u16 = 128;
    let nonce = Fr::from(1337u32);
    let epoch = 5;
    let ctr: u16 = 1;
    let token = info
        .compute_presentation_token(poseidon_params.clone(), epoch, ctr, nonce)
        .unwrap();

    RevealingMultishowChecker {
        token,
        epoch,
        nonce,
        max_num_presentations,
        ctr,
        params: poseidon_params,
    }
}

fn get_agefaceexpiry_checker(info: &PersonalInfo) -> AgeFaceExpiryChecker {
    AgeFaceExpiryChecker {
        age_checker: get_age_checker(),
        face_checker: get_face_checker(info),
        expiry_checker: get_expiry_checker(),
    }
}

/// Returns an instance of an `AgeAndExpiryChecker`. Public parameters are the DOB and expiry dates
fn get_ageexpiry_checker() -> AgeAndExpiryChecker {
    AgeAndExpiryChecker {
        age_checker: get_age_checker(),
        expiry_checker: get_expiry_checker(),
    }
}

fn get_agemultishowexpiry_checker(info: &PersonalInfo) -> AgeMultishowExpiryChecker {
    AgeMultishowExpiryChecker {
        age_checker: get_age_checker(),
        multishow_checker: get_multishow_checker(info),
        expiry_checker: get_expiry_checker(),
    }
}

fn user_prove_tree_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    auth_path: &ComTreePath,
    tree_pk: &TreeProvingKey,
    cred: Com<PassportComScheme>,
) -> TreeProof {
    c.bench_function("Passport: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        })
    });
    auth_path
        .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap()
}

fn user_prove_forest_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    roots: &ComForestRoots,
    auth_path: &ComTreePath,
    forest_pk: &ForestProvingKey,
    cred: Com<PassportComScheme>,
) -> ForestProof {
    c.bench_function("Passport: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(rng, forest_pk, auth_path.root(), cred)
                .unwrap()
        })
    });
    roots
        .prove_membership(rng, forest_pk, auth_path.root(), cred)
        .unwrap()
}

/// User constructs a predicate proof for their age and face
fn user_prove_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    bench_name: &str,
    pk: &PredProvingKey,
    checker: &P,
    info: &PersonalInfo,
    auth_path: &ComTreePath,
) -> PredProof
where
    R: Rng,
    P: Clone
        + PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>,
{
    // Compute the proof wrt the public parameters
    c.bench_function(bench_name, |b| {
        b.iter(|| {
            prove_pred(rng, pk, checker.clone(), info.clone(), auth_path).unwrap();
        })
    });
    let proof = prove_pred(rng, pk, checker.clone(), info.clone(), auth_path).unwrap();

    // DEBUG: Assert that the proof verifies
    assert!(zeronym::pred::verify_pred(
        &pk.prepare_verifying_key(),
        &proof,
        checker,
        &info.commit(),
        &auth_path.root(),
    )
    .unwrap());

    proof
}

fn user_link<R: Rng + CryptoRng>(
    rng: &mut R,
    c: &mut Criterion,
    proof_bench_name: &str,
    verif_bench_name: &str,
    tree_vk: &TreeVerifyingKey,
    forest_vk: &ForestVerifyingKey,
    roots: &ComForestRoots,
    pred_inputs: PredPublicInputs<Bls12_381>,
    pred_vks: Vec<PredVerifyingKey>,
    cred: Com<PassportComScheme>,
    auth_path: &ComTreePath,
    tree_proof: &TreeProof,
    forest_proof: &ForestProof,
    pred_proofs: Vec<PredProof>,
) {
    let gs_crs = GsCrs::rand(rng);
    let link_vk = LinkVerifyingKey {
        gs_crs,
        pred_inputs,
        com_forest_roots: roots.clone(),
        forest_verif_key: forest_vk.clone(),
        tree_verif_key: tree_vk.clone(),
        pred_verif_keys: pred_vks,
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: auth_path.root(),
        forest_proof: forest_proof.clone(),
        tree_proof: tree_proof.clone(),
        pred_proofs,
        vk: link_vk.clone(),
    };

    c.bench_function(proof_bench_name, |b| b.iter(|| link_proofs(rng, &link_ctx)));
    let link_proof = link_proofs(rng, &link_ctx);

    c.bench_function(verif_bench_name, |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk)))
    });

    println!("The bouncer unlatches the velvet rope. The user walks through.");
}

pub fn bench_passport(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // Generate all the Groth16 and Groth-Sahai proving and verifying keys
    let (issuance_pk, issuance_vk) = gen_issuance_crs(&mut rng);
    let (agefaceexpiry_pk, agefaceexpiry_vk) = gen_agefaceexpiry_crs(&mut rng);
    let (agemultishowexpiry_pk, agemultishowexpiry_vk) = gen_agemultishowexpiry_crs(&mut rng);
    let (ageexpiry_pk, ageexpiry_vk) = gen_ageexpiry_crs(&mut rng);
    let (multishow_pk, multishow_vk) = gen_multishow_crs(&mut rng);
    let (expiry_pk, expiry_vk) = gen_expiry_crs(&mut rng);
    let (tree_pk, tree_vk) = gen_tree_crs(&mut rng);
    let (forest_pk, forest_vk) = gen_forest_crs(&mut rng);

    // Generate a random initial state for the issuer
    let mut issuer_state = init_issuer(&mut rng);

    // The user dumps their passport and makes an issuance request
    let (personal_info, issuance_req) = user_req_issuance(&mut rng, c, &issuance_pk);
    let cred = personal_info.commit();

    // The issuer validates the passport and issues the credential
    let auth_path = issue(c, &mut issuer_state, &issuance_vk, &issuance_req);

    let agefaceexpiry_proof = user_prove_pred(
        &mut rng,
        c,
        "Passport: proving age+face+expiry",
        &agefaceexpiry_pk,
        &get_agefaceexpiry_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let agemultishowexpiry_proof = user_prove_pred(
        &mut rng,
        c,
        "Passport: proving age+multishow+expiry",
        &agemultishowexpiry_pk,
        &get_agemultishowexpiry_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let ageexpiry_proof = user_prove_pred(
        &mut rng,
        c,
        "Passport: proving age+expiry",
        &ageexpiry_pk,
        &get_ageexpiry_checker(),
        &personal_info,
        &auth_path,
    );
    let expiry_proof = user_prove_pred(
        &mut rng,
        c,
        "Passport: proving expiry",
        &expiry_pk,
        &get_expiry_checker(),
        &personal_info,
        &auth_path,
    );
    let multishow_proof = user_prove_pred(
        &mut rng,
        c,
        "Passport: proving multishow",
        &multishow_pk,
        &get_multishow_checker(&personal_info),
        &personal_info,
        &auth_path,
    );

    // User gets all the roots from the issuer
    let roots = issuer_state.com_forest.roots();
    // Now user proves tree and forest membership

    let tree_proof = user_prove_tree_memb(&mut rng, c, &auth_path, &tree_pk, cred);
    let forest_proof = user_prove_forest_memb(&mut rng, c, &roots, &auth_path, &forest_pk, cred);

    let pred_inputs = PredPublicInputs::default();
    user_link(
        &mut rng,
        c,
        "Passport: Proving empty linkage",
        "Passport: Verifying empty linkage",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(
        &agefaceexpiry_vk,
        &get_agefaceexpiry_checker(&personal_info),
    );
    user_link(
        &mut rng,
        c,
        "Passport: Proving agefaceexpiry linkage",
        "Passport: Verifying agefaceexpiry linkage",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![agefaceexpiry_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![agefaceexpiry_proof],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(
        &agemultishowexpiry_vk,
        &get_agemultishowexpiry_checker(&personal_info),
    );
    user_link(
        &mut rng,
        c,
        "Passport: Proving agemultishowexpiry linkage",
        "Passport: Verifying agemultishowexpiry linkage",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![agemultishowexpiry_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![agemultishowexpiry_proof],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&expiry_vk, &get_expiry_checker());
    user_link(
        &mut rng,
        c,
        "Passport: Proving expiry linkage",
        "Passport: Verifying expiry linkage",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![expiry_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![expiry_proof],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&ageexpiry_vk, &get_ageexpiry_checker());
    pred_inputs.prepare_pred_checker(&multishow_vk, &get_multishow_checker(&personal_info));
    user_link(
        &mut rng,
        c,
        "Passport: Proving ageexpiry+multishow linkage",
        "Passport: Verifying ageexpiry+multishow linkage",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![ageexpiry_vk, multishow_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![ageexpiry_proof, multishow_proof],
    );
}
