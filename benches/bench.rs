use merkle_bench::constraints::MerkleProofCircuit;

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_crypto_primitives::{
    crh::{
        bowe_hopwood,
        constraints::{CRHGadget, TwoToOneCRHGadget},
        pedersen, TwoToOneCRH, CRH,
    },
    merkle_tree::{Config, LeafDigest, LeafParam, Path, TwoToOneDigest, TwoToOneParam},
    Error as ArkError,
};
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsParameters, EdwardsProjective as JubJub, Fq,
};
use ark_ff::{to_bytes, ToConstraintField};
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
const LOG_NUM_LEAVES: u32 = 3;

#[inline]
fn tree_height(num_leaves: usize) -> usize {
    if num_leaves == 1 {
        return 1;
    }

    (ark_std::log2(num_leaves) as usize) + 1
}

fn rand_leaf_hash<C: Config, R: Rng>(
    leaf_crh_params: &LeafParam<C>,
    rng: &mut R,
) -> Result<LeafDigest<C>, ArkError> {
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);
    C::LeafHash::evaluate(&leaf_crh_params, &buf)
}

fn rand_two_to_one_hash<C: Config, R: Rng>(
    two_to_one_crh_params: &TwoToOneParam<C>,
    rng: &mut R,
) -> Result<TwoToOneDigest<C>, ArkError> {
    let mut buf1 = [0u8; 8];
    let mut buf2 = [0u8; 8];
    rng.fill_bytes(&mut buf1);
    rng.fill_bytes(&mut buf2);
    C::TwoToOneHash::evaluate(&two_to_one_crh_params, &buf1, &buf2)
}

/// Returns a random path and root hash
fn rand_path<C: Config, R: Rng>(
    leaf: &Leaf,
    num_leaves: usize,
    leaf_crh_params: &LeafParam<C>,
    two_to_one_crh_params: &TwoToOneParam<C>,
    rng: &mut R,
) -> Result<(Path<C>, TwoToOneDigest<C>), ArkError> {
    let height = tree_height(num_leaves);

    // Compute the leaf hash
    let leaf_hash = C::LeafHash::evaluate(&leaf_crh_params, &ark_ff::to_bytes!(&leaf)?)?;

    // Make a random sibling hash and random auth path hashes. auth_path.len() = `height - 2`.
    // The two missing elements being the leaf sibling hash and the root.
    let leaf_sibling_hash = rand_leaf_hash::<C, _>(leaf_crh_params, rng)?;
    let auth_path = (0..height - 2)
        .map(|_| rand_two_to_one_hash::<C, _>(&two_to_one_crh_params, rng))
        .collect::<Result<Vec<TwoToOneDigest<C>>, ArkError>>()?;
    println!("auth path len == {}", auth_path.len());

    // Use index 0 so that all siblings to the root are right-siblings
    //let leaf_index = 2usize.pow(height as u32 - 1) - 1;
    let leaf_index = 0;
    println!("leaf index {:b}", leaf_index);

    // Calculate the root digest. Every sibling is a right-sibling
    let mut cur_digest = C::TwoToOneHash::evaluate(
        &two_to_one_crh_params,
        &to_bytes!(leaf_hash)?,
        &to_bytes!(leaf_sibling_hash)?,
    )?;
    for sibling in &auth_path {
        cur_digest = C::TwoToOneHash::evaluate(
            &two_to_one_crh_params,
            &to_bytes!(cur_digest)?,
            &to_bytes!(sibling)?,
        )?;
    }

    let root = cur_digest;
    let path = Path {
        leaf_sibling_hash,
        auth_path,
        leaf_index,
    };

    Ok((path, root))
}

/*
fn path_root<C: Config>(
    path: &Path<C>,
    leaf_hash: &LeafDigest<C>,
    two_to_one_crh_params: &TwoToOneParam<C>,
) -> Result<TwoToOneDigest<C>, ArkError> {
    let mut cur_digest = C::TwoToOneHash::evaluate(
        &two_to_one_crh_params,
        &to_bytes!(leaf_hash)?,
        &to_bytes!(path.leaf_sibling_hash)?,
    )?;

    for sibling in &path.auth_path {
        cur_digest = C::TwoToOneHash::evaluate(
            &two_to_one_crh_params,
            &to_bytes!(cur_digest)?,
            &to_bytes!(sibling)?,
        )?;
    }

    Ok(cur_digest)
}
*/

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

    for num_trees in (0..LOG_NUM_LEAVES).map(|i| 2usize.pow(i)) {
        let num_leaves_per_tree = num_leaves / num_trees;

        // Prove an element of the first tree
        let leaf: Leaf = rng.gen();
        let (auth_path, first_root) = rand_path(
            &leaf,
            num_leaves_per_tree,
            &leaf_crh_params,
            &two_to_one_crh_params,
            &mut rng,
        )
        .unwrap();

        // For the remaining trees, just compute the roots
        let remaining_roots: Vec<TwoToOneDigest<C>> = (1..num_trees)
            .map(|_| rand_two_to_one_hash::<C, _>(&two_to_one_crh_params, &mut rng).unwrap())
            .collect();

        let roots = &[vec![first_root], remaining_roots].concat();
        println!("num_roots == {}", roots.len());

        // Due to a bug, the path can never be None. It can be any vec of the correct length
        let (placeholder_path, _) = rand_path(
            &[0u8; LEAF_SIZE],
            num_leaves_per_tree,
            &leaf_crh_params,
            &two_to_one_crh_params,
            &mut rng,
        )
        .unwrap();
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
                "Proving membership over 2^{:0.0} trees of 2^{:0.0} leaves, using {}",
                (num_trees as f32).log2(),
                ((num_leaves / num_trees) as f32).log2(),
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

fn bench_pedersen(c: &mut Criterion) {
    #[derive(Clone, PartialEq, Eq, Hash)]
    struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type HG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window>;

    #[derive(Clone)]
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = pedersen::CRH<JubJub, Window>;
        type TwoToOneHash = pedersen::CRH<JubJub, Window>;
    }

    bench_with_hash::<JubJubMerkleTreeParams, HG>("Pedersen", c);
}

fn bench_bowe_hopwood(c: &mut Criterion) {
    use ark_ed_on_bls12_381::constraints::FqVar;

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63;
        const NUM_WINDOWS: usize = 17;
    }

    type H = bowe_hopwood::CRH<EdwardsParameters, Window>;
    type HG = bowe_hopwood::constraints::CRHGadget<EdwardsParameters, FqVar>;

    #[derive(Clone)]
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }

    bench_with_hash::<JubJubMerkleTreeParams, HG>("Bowe-Hopwood", c);
}

criterion_group!(benches, /*bench_pedersen ,*/ bench_bowe_hopwood);
criterion_main!(benches);
