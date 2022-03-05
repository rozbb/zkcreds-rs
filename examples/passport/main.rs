mod ark_sha256;
mod issuance_checker;
mod params;
mod passport_dump;
mod passport_info;
mod sig_verif;

use crate::{
    issuance_checker::IssuanceChecker,
    params::{PassportComScheme, PassportComSchemeG, H, HG},
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
    sig_verif::{load_usa_pubkey, IssuerPubkey},
};

use zeronym::{
    attrs::Attrs,
    pred::{gen_pred_crs, prove_pred, verify_pred},
};

use std::fs::File;

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::TwoToOneCRH;

fn load_dump() -> PassportDump {
    let file = File::open("examples/passport/full_dump.json").unwrap();
    serde_json::from_reader(file).unwrap()
}

fn check_sig(pk: &IssuerPubkey, sig: &[u8], hash: &[u8]) {
    assert!(pk.verify(sig, hash));
}

fn check_issuance(attrs: PersonalInfo, checker: IssuanceChecker) {
    let mut rng = ark_std::test_rng();

    // Commit to the attributes. This is what the issuer sees
    let cred = attrs.commit();

    // Make the CRS. The merkle root doesn't matter for now
    let pk = gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(&mut rng, checker.clone())
    .unwrap();
    println!("Made issuance predicate CRS");
    let vk = pk.prepare_verifying_key();
    let merkle_root = <H as TwoToOneCRH>::Output::default();

    // Prove that the attributes match the econtent hash of the passport, that the passport is
    // not expired, and the passport is issued by the US
    let proof = prove_pred(&mut rng, &pk, checker.clone(), attrs, merkle_root).unwrap();
    println!("Proved issuance predicate");

    // Verify the above
    assert!(verify_pred(&vk, &proof, &checker, &cred, &merkle_root).unwrap());
    println!("Verified issuance predicate");
}

fn main() {
    let mut rng = ark_std::test_rng();

    // Load the US State Dept. pubkey
    let usa_pubkey = load_usa_pubkey();

    // Load the passport
    let dump = load_dump();
    let attrs = PersonalInfo::from_passport(&mut rng, &dump);

    // Check that the attributes match the econtent hash of the passport, that the passport is
    // not expired, and the passport is issued by the US
    let today = 220101u32;
    let hash_checker = IssuanceChecker::from_passport(&dump, *b"USA", today);
    check_issuance(attrs, hash_checker);

    // Check that the econtent hash is signed by the US State Dept
    check_sig(&usa_pubkey, &dump.sig, &dump.econtent_hash());
    println!("Passport signature verifies");
}
