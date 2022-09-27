use crate::microbenches::tf_proof::{gen_tf_crs, prove_tf, verify_tf};

use linkg16::groth16;
use zkcreds::{
    attrs::Attrs,
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    poseidon_utils::{Bls12PoseidonCommitter, Bls12PoseidonCrh},
    test_util::{NameAndBirthYear, MERKLE_CRH_PARAM},
    Com,
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use criterion::Criterion;

type TestCom = Bls12PoseidonCommitter;
type TestComG = Bls12PoseidonCommitter;
type TestTreeH = Bls12PoseidonCrh;
type TestTreeHG = Bls12PoseidonCrh;

/// Tests a predicate that returns true iff the given `NameAndBirthYear` is at least 21
pub fn bench_tree_forest(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // Make a attribute to put in the tree
    let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
    let person_com = Attrs::<_, TestCom>::commit(&person);

    for log2_num_leaves in [15, 31, 47, 63] {
        for log2_num_trees in 0..16 {
            let tree_height = (log2_num_leaves + 1) - log2_num_trees;
            let num_trees = 2usize.pow(log2_num_trees);

            // SparseMerkleTree requires trees of height ≥ 2. And the placeholder monolithic proof
            // fails for height = 2 for some reason and I don't care why
            if tree_height <= 2 {
                continue;
            }

            // Generate the tree and forest circuits' CRS
            let tree_pk = gen_tree_memb_crs::<
                _,
                E,
                NameAndBirthYear,
                TestCom,
                TestComG,
                TestTreeH,
                TestTreeHG,
            >(&mut rng, (), tree_height)
            .unwrap();
            let forest_pk = gen_forest_memb_crs::<
                _,
                E,
                NameAndBirthYear,
                TestCom,
                TestComG,
                TestTreeH,
                TestTreeHG,
            >(&mut rng, num_trees)
            .unwrap();

            // Set up an auth path for tree membership
            let auth_path = {
                let leaf_idx = 0;
                let mut tree = ComTree::<_, TestTreeH, TestCom>::empty((), tree_height);
                tree.insert(leaf_idx, &person_com)
            };
            let member_root = auth_path.root();

            // Make an empty forest of the correct size and prove membership of the 0th root
            let mut roots = ComForestRoots::<Fr, TestTreeH>::new(num_trees);
            roots.roots[0] = member_root;

            // Benchmark the tree and forest proofs in serial
            c.bench_function(
                &format!(
                    "Proving tree+forest [lnl={},th={}]",
                    log2_num_leaves, tree_height
                ),
                |b| {
                    b.iter(|| {
                        auth_path
                            .prove_membership(&mut rng, &tree_pk, &(), Com::<TestCom>::default())
                            .unwrap();
                        roots
                            .prove_membership(&mut rng, &forest_pk, member_root, person_com)
                            .unwrap();
                    });
                },
            );

            let tf_pk: groth16::ProvingKey<E> =
                gen_tf_crs::<_, E, TestCom, TestComG, TestTreeH, TestTreeHG>(
                    &mut rng,
                    (),
                    tree_height,
                    num_trees,
                )
                .unwrap();
            let tf_vk = tf_pk.verifying_key();
            c.bench_function(
                &format!(
                    "Proving treeforest [lnl={},th={}]",
                    log2_num_leaves, tree_height
                ),
                |b| {
                    b.iter(|| {
                        prove_tf::<_, E, TestCom, TestComG, TestTreeH, TestTreeHG>(
                            &mut rng,
                            &tf_pk,
                            &(),
                            &roots,
                            &auth_path,
                            person_com,
                        )
                        .unwrap()
                    })
                },
            );
            let proof = prove_tf::<_, E, TestCom, TestComG, TestTreeH, TestTreeHG>(
                &mut rng,
                &tf_pk,
                &(),
                &roots,
                &auth_path,
                person_com,
            )
            .unwrap();
            c.bench_function(
                &format!(
                    "Veryfing treeforest [lnl={},th={}]",
                    log2_num_leaves, tree_height
                ),
                |b| {
                    b.iter(|| {
                        assert!(verify_tf::<E, TestCom, TestComG, TestTreeH, TestTreeHG>(
                            &tf_vk, &roots, &proof,
                        )
                        .unwrap())
                    })
                },
            );
        }
    }
}
