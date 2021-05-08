use merkle_bench::{
    constraints::MerkleProofCircuit,
    merkle_forest::{idx_1d_to_2d, MerkleForest},
    test_util::Window4x256,
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_crypto_primitives::{
    crh::{
        constraints::{CRHGadget, TwoToOneCRHGadget},
        pedersen, TwoToOneCRH, CRH,
    },
    merkle_tree::{Config, LeafParam, TwoToOneParam},
    snark::SNARK,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
use ark_ff::ToConstraintField;
use ark_groth16::Groth16;
use ark_std::rand::Rng;
use criterion::{criterion_group, criterion_main, Criterion};

const LEAF_SIZE: usize = 8;
type Leaf = [u8; LEAF_SIZE];

pub fn bench_with_hash<C, HG>(hash_name: &str, c: &mut Criterion)
where
    C: Config + Clone,
    <<C as Config>::TwoToOneHash as TwoToOneCRH>::Output: ToConstraintField<Fr>,
    HG: CRHGadget<C::LeafHash, Fr> + TwoToOneCRHGadget<C::TwoToOneHash, Fr>,
{
    let mut rng = ark_std::test_rng();

    // Setup hashing params
    let leaf_crh_params: LeafParam<C> = <C::LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params: TwoToOneParam<C> =
        <C::TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // num_trees can be arbitrary, and num_leaves has to be num_trees * 2^k for some k
    let num_trees = 5;
    let num_leaves = num_trees * 2usize.pow(8);

    // Randomly generate the appropriate number of leaves
    let leaves: Vec<Leaf> = (0..num_leaves).map(|_| rng.gen()).collect();

    // Create the forest
    let forest = MerkleForest::<C>::new(
        &leaf_crh_params.clone(),
        &two_to_one_crh_params.clone(),
        &leaves,
        num_trees,
    )
    .unwrap();

    // Pick the leaf at index 106 to make a proof of
    let (leaf, auth_path) = {
        let i = 106;
        let (tree_idx, leaf_idx) = idx_1d_to_2d(i, num_trees, num_leaves);
        let tree = &forest.trees[tree_idx];
        let leaf = &leaves[i];
        let auth_path = tree.generate_proof(leaf_idx).unwrap();

        (leaf, auth_path)
    };

    // Due to a bug, the path can never be None
    let placeholder_path = &forest.trees[0].generate_proof(0).unwrap();
    let param_gen_circuit =
        MerkleProofCircuit::<Fq, HG, C, HG>::new(&forest, placeholder_path, &[0u8; LEAF_SIZE]);
    /* This doesn't work because you can't make a ZK PathVar
    let param_gen_circuit =
        MerkleProofCircuit::<Fq, HG, JubJubMerkleTreeParams, HG>::new_placeholder(
            &forest, LEAF_SIZE,
        );
    */

    let (pk, vk) = Groth16::<E>::circuit_specific_setup(param_gen_circuit, &mut rng).unwrap();

    // Construct the circuit which will prove the membership of leaf i, and prove it
    let circuit = MerkleProofCircuit::<Fq, HG, C, HG>::new(&forest, &auth_path, &leaf.clone());

    c.bench_function(
        &format!(
            "Merkle proof on {} trees of {} leaves, using {}",
            num_trees,
            num_leaves / num_trees,
            hash_name
        ),
        |b| {
            b.iter(|| {
                Groth16::<E>::prove(&pk, circuit.clone(), &mut rng).unwrap();
            });
        },
    );
    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    // Now construct the verification information
    let roots: Vec<Fr> = forest
        .roots()
        .into_iter()
        .flat_map(|root| root.to_field_elements().unwrap())
        .collect();
    assert!(Groth16::<E>::verify(&vk, &roots, &proof).unwrap());
}

fn pedersen(c: &mut Criterion) {
    type HG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;

    #[derive(Clone)]
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = pedersen::CRH<JubJub, Window4x256>;
        type TwoToOneHash = pedersen::CRH<JubJub, Window4x256>;
    }

    bench_with_hash::<JubJubMerkleTreeParams, HG>("Pedersen", c);
}

criterion_group!(benches, pedersen);
criterion_main!(benches);
