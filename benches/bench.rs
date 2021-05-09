use merkle_bench::{constraints::MerkleProofCircuit, test_util::Window4x256};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_crypto_primitives::{
    crh::{
        constraints::{CRHGadget, TwoToOneCRHGadget},
        pedersen, TwoToOneCRH, CRH,
    },
    merkle_tree::{Config, LeafParam, MerkleTree, TwoToOneDigest, TwoToOneParam},
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
use ark_ff::ToConstraintField;
use ark_groth16::{
    generator::generate_random_parameters,
    prover::create_random_proof,
    verifier::{prepare_inputs, prepare_verifying_key, verify_proof_with_prepared_inputs},
};
use ark_std::rand::Rng;
use criterion::{criterion_group, criterion_main, Criterion};

// The size of the leaf really doesn't matter for benchmarking time. Keep it small because
// otherwise the Merkle trees are gonna be massive
const LEAF_SIZE: usize = 1;
type Leaf = [u8; LEAF_SIZE];

// The number of leaves in the Merkle forest
const LOG_NUM_LEAVES: u32 = 32;

pub fn bench_with_hash<C, HG>(hash_name: &str, c: &mut Criterion)
where
    C: Config + Clone,
    <<C as Config>::TwoToOneHash as TwoToOneCRH>::Output: ToConstraintField<Fr>,
    HG: CRHGadget<C::LeafHash, Fr> + TwoToOneCRHGadget<C::TwoToOneHash, Fr>,
{
    let mut rng = ark_std::test_rng();
    let num_leaves = 2usize.pow(LOG_NUM_LEAVES);

    // Setup hashing params
    let leaf_crh_params: LeafParam<C> = <C::LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params: TwoToOneParam<C> =
        <C::TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Setup a single big tree
    println!("Making leaves");
    let mut first_tree_leaves: Vec<Leaf> = Vec::with_capacity(num_leaves);
    for _ in 0..num_leaves {
        first_tree_leaves.push(rng.gen());
    }

    for num_trees in (0..LOG_NUM_LEAVES).map(|i| 2usize.pow(i)) {
        let num_leaves_per_tree = num_leaves / num_trees;

        // Prove an element of the first tree
        println!("Making first merkle tree");
        let (leaf, auth_path, first_root) = {
            // Truncate the leaves we allocated to the tree size we want
            let first_tree = MerkleTree::<C>::new(
                &leaf_crh_params.clone(),
                &two_to_one_crh_params.clone(),
                &first_tree_leaves[..num_leaves_per_tree],
            )
            .unwrap();

            // Prove the 12th leaf. This is totally arbitrary
            let i = 12;
            let leaf = first_tree_leaves[i].clone();
            let auth_path = first_tree.generate_proof(i).unwrap();

            (leaf, auth_path, first_tree.root())
        };

        println!("Making remaining roots");
        // For the remaining trees, just compute the roots
        let remaining_roots: Vec<TwoToOneDigest<C>> = (1..num_trees)
            .map(|_| {
                let left_bytes: [u8; 8] = rng.gen();
                let right_bytes: [u8; 8] = rng.gen();
                C::TwoToOneHash::evaluate(&two_to_one_crh_params, &left_bytes, &right_bytes)
                    .unwrap()
            })
            .collect();

        let roots = &[vec![first_root], remaining_roots].concat();

        // Due to a bug, the path can never be None. It can be any vec of the correct length
        let placeholder_path = {
            let leaves: Vec<Leaf> = (0..num_leaves_per_tree).map(|_| rng.gen()).collect();
            let tree =
                MerkleTree::<C>::new(&leaf_crh_params, &two_to_one_crh_params, &leaves).unwrap();
            tree.generate_proof(0).unwrap()
        };
        let param_gen_circuit = MerkleProofCircuit::<Fq, HG, C, HG>::new(
            &roots,
            &leaf_crh_params,
            &two_to_one_crh_params,
            &placeholder_path,
            &[0u8; LEAF_SIZE],
        );
        /* This doesn't work because you can't make a ZK PathVar
        let param_gen_circuit =
            MerkleProofCircuit::<Fq, HG, JubJubMerkleTreeParams, HG>::new_placeholder(
                &forest, LEAF_SIZE,
            );
        */
        let pk = generate_random_parameters::<E, _, _>(param_gen_circuit, &mut rng).unwrap();

        // Construct the circuit which will prove the membership of leaf i, and prove it
        let circuit = MerkleProofCircuit::<Fq, HG, C, HG>::new(
            &roots,
            &leaf_crh_params,
            &two_to_one_crh_params,
            &auth_path,
            &leaf.clone(),
        );

        // Prove
        c.bench_function(
            &format!(
                "Proving membership over {} trees of {} leaves, using {}",
                num_trees,
                num_leaves / num_trees,
                hash_name
            ),
            |b| {
                b.iter(|| {
                    create_random_proof::<E, _, _>(circuit.clone(), &pk, &mut rng).unwrap();
                });
            },
        );
        let proof = create_random_proof::<E, _, _>(circuit.clone(), &pk, &mut rng).unwrap();

        // Now construct the verification information. Serialize the roots into field elems
        let roots_input: Vec<Fr> = roots
            .into_iter()
            .flat_map(|root| root.to_field_elements().unwrap())
            .collect();

        // Verify
        let pvk = prepare_verifying_key(&pk.vk);
        let prepared_inputs = prepare_inputs(&pvk, &roots_input).unwrap();
        assert!(verify_proof_with_prepared_inputs(&pvk, &proof, &prepared_inputs).unwrap());
        c.bench_function(
            &format!(
                "Verifying membership over {} trees of {} leaves, using {}",
                num_trees,
                num_leaves / num_trees,
                hash_name
            ),
            |b| {
                b.iter(|| {
                    verify_proof_with_prepared_inputs(&pvk, &proof, &prepared_inputs).unwrap()
                });
            },
        );
    }
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
