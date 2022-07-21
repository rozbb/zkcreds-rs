use zkcreds::{
    attrs::{AccountableAttrs, Attrs},
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    pred::{gen_pred_crs, prove_pred},
    revealing_multishow::{MultishowableAttrs, RevealingMultishowChecker},
    test_util::{AgeChecker, NameAndBirthYear, NameAndBirthYearVar},
    utils::{setup_poseidon_params, Bls12PoseidonCommitter, Bls12PoseidonCrh},
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::UniformRand;
use arkworks_utils::Curve;
use criterion::Criterion;

const POSEIDON_WIDTH: u8 = 5;
const EIGHTEEN_YEARS_AGO: u16 = 2004;
const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

type TestTreeH = Bls12PoseidonCrh;
type TestTreeHG = Bls12PoseidonCrh;

pub fn bench_multishow_age(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    //
    // Generate CRSs
    //

    // Forest predicate
    let forest_pk = gen_forest_memb_crs::<
        _,
        E,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >(&mut rng, NUM_TREES)
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    // Tree predicate
    let tree_pk = gen_tree_memb_crs::<
        _,
        E,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >(&mut rng, (), TREE_HEIGHT)
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();

    // Age predicate
    // We choose that anyone born in 2004 or earlier satisfies our predicate
    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
    };
    let age_pk =
        gen_pred_crs::<_, _, E, _, _, _, _, TestTreeH, TestTreeHG>(&mut rng, age_checker.clone())
            .unwrap();
    let age_vk = age_pk.prepare_verifying_key();

    // Multishow predicate
    let poseidon_params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
    let epoch = 5;
    let max_num_presentations: u16 = 128;
    let multishow_pk = {
        let checker = RevealingMultishowChecker {
            params: poseidon_params.clone(),
            ..Default::default()
        };
        gen_pred_crs::<_, _, E, _, NameAndBirthYearVar, _, _, TestTreeH, TestTreeHG>(
            &mut rng, checker,
        )
        .unwrap()
    };
    let multishow_vk = multishow_pk.prepare_verifying_key();

    //
    // Start proving things
    //

    // Make a attribute to put in the tree
    let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
    let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person);

    // Make a tree and "issue", i.e., put the person commitment in the tree at index 17
    let leaf_idx = 17;
    let mut tree = ComTree::empty((), TREE_HEIGHT);
    let auth_path = tree.insert(leaf_idx, &person_com);

    // The person can now prove membership in the tree. Calculate the root and prove wrt that
    // root.
    let merkle_root = tree.root();
    c.bench_function("Age+Multishow: proving tree membership", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(&mut rng, &tree_pk, &(), person_com)
                .unwrap()
        })
    });
    let tree_proof = auth_path
        .prove_membership(&mut rng, &tree_pk, &(), person_com)
        .unwrap();

    // Prove that the tree is in the forest
    // Make a forest of 10 trees, with our tree occursing at a random index in the forest
    let mut roots = ComForestRoots::new(NUM_TREES - 1);
    let root = tree.root();
    roots.roots.push(root);
    c.bench_function("Age+Multishow: proving forest membership", |b| {
        b.iter(|| {
            roots
                .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
                .unwrap()
        })
    });
    let forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
        .unwrap();

    // User computes a multishow token
    let nonce = Fr::rand(&mut rng);
    let ctr: u16 = 1;
    let token = MultishowableAttrs::<_, Bls12PoseidonCommitter>::compute_presentation_token(
        &person,
        poseidon_params.clone(),
        epoch,
        ctr,
        nonce,
    )
    .unwrap();
    // Prove the multishow predicate
    // User constructs a checker for their predicate
    let multishow_checker = RevealingMultishowChecker {
        token,
        epoch,
        nonce,
        max_num_presentations,
        ctr,
        params: poseidon_params,
    };
    c.bench_function("Age+Multishow: proving multishow", |b| {
        b.iter(|| {
            prove_pred(
                &mut rng,
                &multishow_pk,
                multishow_checker.clone(),
                person.clone(),
                &auth_path,
            )
            .unwrap()
        })
    });
    let multishow_proof = prove_pred(
        &mut rng,
        &multishow_pk,
        multishow_checker.clone(),
        person.clone(),
        &auth_path,
    )
    .unwrap();

    // Prove the predicate
    c.bench_function("Age+Multishow: proving age", |b| {
        b.iter(|| {
            prove_pred(
                &mut rng,
                &age_pk,
                age_checker.clone(),
                person.clone(),
                &auth_path,
            )
            .unwrap()
        })
    });
    let age_proof = prove_pred(&mut rng, &age_pk, age_checker.clone(), person, &auth_path).unwrap();

    // Collect the predicate public inputs
    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&age_vk, &age_checker);
    pred_inputs.prepare_pred_checker(&multishow_vk, &multishow_checker);

    // Now link everything together
    let link_vk = LinkVerifyingKey {
        pred_inputs: pred_inputs.clone(),
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk,
        tree_verif_key: tree_vk,
        pred_verif_keys: vec![age_vk, multishow_vk],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: person_com,
        merkle_root: root,
        forest_proof,
        tree_proof,
        pred_proofs: vec![age_proof, multishow_proof],
        vk: link_vk.clone(),
    };
    c.bench_function("Age+Multishow: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let link_proof = link_proofs(&mut rng, &link_ctx);
    crate::util::record_size("Age+Multishow", &link_proof);

    // Verify the link proof
    c.bench_function("Age+Multishow: Verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });
}
