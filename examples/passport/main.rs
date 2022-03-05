mod ark_sha256;
mod issuance_checker;
mod params;
mod passport_dump;
mod passport_info;

use crate::{
    issuance_checker::IssuanceChecker,
    params::{PassportComScheme, PassportComSchemeG, H, HG},
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
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

fn check_issuance(attrs: PersonalInfo, checker: IssuanceChecker) {
    let mut rng = ark_std::test_rng();

    println!("Making issuance predicate CRS");
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
    let merkle_root = <H as TwoToOneCRH>::Output::default();
    let cred = attrs.commit();

    println!("Proving issuance predicate");
    let proof = prove_pred(&mut rng, &pk, checker.clone(), attrs, merkle_root).unwrap();

    println!("Verifying issuance predicate");
    let vk = pk.prepare_verifying_key();
    assert!(verify_pred(&vk, &proof, &checker, &cred, &merkle_root).unwrap());
    println!("Verified");
}

fn main() {
    let mut rng = ark_std::test_rng();

    // Make sure the passport did not expire before Jan 1, 2022
    let today = 220101u32;
    // Load the passport
    let dump = load_dump();
    let attrs = PersonalInfo::from_passport(&mut rng, &dump);
    let checker = IssuanceChecker::from_passport(&dump, *b"USA", today);
    check_issuance(attrs, checker);
}
