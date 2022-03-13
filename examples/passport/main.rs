mod ark_sha256;
mod issuance_checker;
mod params;
mod passport_dump;
mod passport_info;
mod preds;
mod sig_verif;

use crate::{
    issuance_checker::{IssuanceReq, PassportHashChecker},
    params::{
        ComForest, ComTree, ComTreePath, ForestProvingKey, ForestVerifyingKey, PassportComScheme,
        PassportComSchemeG, PredProof, PredProvingKey, PredVerifyingKey, TreeProvingKey,
        TreeVerifyingKey, H, HG, MERKLE_CRH_PARAM, SIG_HASH_LEN, STATE_ID_LEN,
    },
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
    preds::AgeAndFaceChecker,
    sig_verif::{load_usa_pubkey, IssuerPubkey},
};

use zeronym::{
    attrs::Attrs,
    pred::{prove_birth, prove_pred, verify_birth, verify_pred},
    Com,
};

use std::fs::File;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_std::rand::Rng;

const TREE_HEIGHT: u32 = 32;
const FOREST_SIZE: usize = 10;

// Sample parameters for passport validation. All passports must expire some time after TODAY, and
// must have nationality USER_NATIONALITY
const TODAY: u32 = 220101u32;
const USER_NATIONALITY: [u8; STATE_ID_LEN] = *b"USA";

fn load_dump() -> PassportDump {
    let file = File::open("examples/passport/full_dump.json").unwrap();
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
    let trees = (0..FOREST_SIZE).map(|_| rand_tree(rng)).collect();
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

fn gen_ageface_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
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
    >(rng, AgeAndFaceChecker::default())
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
    >(rng, FOREST_SIZE)
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

/// Makes a random new issuer state
fn init_issuer<R: Rng>(rng: &mut R) -> IssuerState {
    let com_forest = rand_forest(rng);
    let next_free_tree = rng.gen_range(0..FOREST_SIZE);
    let next_free_leaf = rng.gen_range(0..2u64.pow(TREE_HEIGHT));

    IssuerState {
        com_forest,
        next_free_tree,
        next_free_leaf,
    }
}

/// An issuer takes an issuance request and validates it
fn issue(state: &mut IssuerState, birth_vk: &PredVerifyingKey, req: &IssuanceReq) -> ComTreePath {
    // Check that the hash was computed correctly
    let checker = PassportHashChecker::from_issuance_req(req, USER_NATIONALITY, TODAY);
    assert!(verify_birth(birth_vk, &req.hash_proof, &checker, &req.attrs_com).unwrap());

    // Now check that the signature of the hash is correct
    let sig_pubkey = load_usa_pubkey();
    assert!(sig_pubkey.verify(&req.sig, &req.econtent_hash));

    // Insert
    state.com_forest.trees[state.next_free_tree].insert(state.next_free_leaf, &req.attrs_com)
}

/// With their passport, a user constructs a `PersonalInfo` struct and requests issuance
fn user_req_issuance<R: Rng>(
    rng: &mut R,
    issuance_pk: &PredProvingKey,
) -> (PersonalInfo, IssuanceReq) {
    // Load the passport and parse it into a `PersonalInfo` struct
    let dump = load_dump();
    let my_info = PersonalInfo::from_passport(rng, &dump);
    let attrs_com = my_info.commit();

    // Make a hash checker struct using our private data
    let hash_checker = PassportHashChecker::from_passport(&dump, USER_NATIONALITY, TODAY);

    // Prove the passport hash is correctly computed
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

/// User constructs a predicate proof for their age and face
fn user_prove_ageface<R: Rng>(
    rng: &mut R,
    ageface_pk: &PredProvingKey,
    info: &PersonalInfo,
    auth_path: &ComTreePath,
) -> PredProof {
    //let twenty_one_years_ago = TODAY - 210000;
    let twenty_one_years_ago = 980101u32;
    let ageface_checker = AgeAndFaceChecker {
        threshold_birth_date: Fr::from(twenty_one_years_ago),
        face_hash: info.biometrics_hash(),
    };
    prove_pred(rng, ageface_pk, ageface_checker, info.clone(), auth_path).unwrap()
}

// DEBUG: Verify the ageface Groth16 predicate proof. This cannot be verified by anyone but the
// user themselves
fn user_verify_ageface(
    ageface_vk: &PredVerifyingKey,
    ageface_proof: &PredProof,
    info: &PersonalInfo,
    auth_path: &ComTreePath,
) {
    // Reconstruct the AgeAndFaceChecker used by the prover
    //let twenty_one_years_ago = TODAY - 210000;
    let twenty_one_years_ago = 980101u32;
    let ageface_checker = AgeAndFaceChecker {
        threshold_birth_date: Fr::from(twenty_one_years_ago),
        face_hash: info.biometrics_hash(),
    };
    // Assert that the proof verifies
    assert!(zeronym::pred::verify_pred(
        ageface_vk,
        ageface_proof,
        &ageface_checker,
        &info.commit(),
        &auth_path.root(),
    )
    .unwrap());
}

fn main() {
    let mut rng = ark_std::test_rng();

    // Generate all the Groth16 and Groth-Sahai proving and verifying keys
    let (issuance_pk, issuance_vk) = gen_issuance_crs(&mut rng);
    let (ageface_pk, ageface_vk) = gen_ageface_crs(&mut rng);
    println!("Generated CRSs");

    // Generate a random initial state for the issuer
    let mut issuer_state = init_issuer(&mut rng);

    // The user dumps their passport and makes an issuance request
    println!("Requesting issuance");
    let (personal_info, issuance_req) = user_req_issuance(&mut rng, &issuance_pk);
    let cred = personal_info.commit();

    // The issuer validates the passport and issues the credential
    let auth_path = issue(&mut issuer_state, &issuance_vk, &issuance_req);
    println!("Issuance request granted");

    //
    // A user walks into a bar...
    //

    // User wants to prove age and face. They precompute this
    let ageface_proof = user_prove_ageface(&mut rng, &ageface_pk, &personal_info, &auth_path);
    // DEBUG
    user_verify_ageface(&ageface_vk, &ageface_proof, &personal_info, &auth_path);
}
