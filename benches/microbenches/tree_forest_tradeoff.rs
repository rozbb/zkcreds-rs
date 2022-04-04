use crate::microbenches::tf_proof::{gen_tf_crs, prove_tf, verify_tf};

use zeronym::{
    attrs::Attrs,
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    test_util::{
        NameAndBirthYear, TestComScheme, TestComSchemeG, TestTreeH, TestTreeHG, MERKLE_CRH_PARAM,
    },
    Com,
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use criterion::Criterion;

/// Tests a predicate that returns true iff the given `NameAndBirthYear` is at least 21
pub fn bench_tree_forest(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // Make a attribute to put in the tree
    let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
    let person_com = person.commit();

    for log2_num_leaves in [15, 31, 47, 63] {
        for log2_num_trees in 0..16 {
            let tree_height = (log2_num_leaves + 1) - log2_num_trees;
            let num_trees = 2usize.pow(log2_num_trees);

            // SparseMerkleTree requires trees of height ≥ 2
            if tree_height < 2 {
                continue;
            }

            // Generate the tree and forest circuits' CRS
            let tree_pk = gen_tree_memb_crs::<
                _,
                E,
                NameAndBirthYear,
                TestComScheme,
                TestComSchemeG,
                TestTreeH,
                TestTreeHG,
            >(&mut rng, MERKLE_CRH_PARAM.clone(), tree_height)
            .unwrap();
            let forest_pk = gen_forest_memb_crs::<
                _,
                E,
                NameAndBirthYear,
                TestComScheme,
                TestComSchemeG,
                TestTreeH,
                TestTreeHG,
            >(&mut rng, num_trees)
            .unwrap();

            // Set up an auth path for tree membership
            let auth_path = {
                let leaf_idx = 0;
                let mut tree = ComTree::<_, TestTreeH, TestComScheme>::empty(
                    MERKLE_CRH_PARAM.clone(),
                    tree_height,
                );
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
                            .prove_membership(
                                &mut rng,
                                &tree_pk,
                                &*MERKLE_CRH_PARAM,
                                Com::<TestComScheme>::default(),
                            )
                            .unwrap();
                        roots
                            .prove_membership(&mut rng, &forest_pk, member_root, person_com)
                            .unwrap();
                    });
                },
            );

            let tf_pk: ark_groth16::ProvingKey<E> =
                gen_tf_crs::<_, E, TestComScheme, TestComSchemeG, TestTreeH, TestTreeHG>(
                    &mut rng,
                    MERKLE_CRH_PARAM.clone(),
                    tree_height,
                    num_trees,
                )
                .unwrap();
            let tf_pvk = ark_groth16::prepare_verifying_key(&tf_pk.vk);
            c.bench_function(
                &format!(
                    "Proving treeforest [lnl={},th={}]",
                    log2_num_leaves, tree_height
                ),
                |b| {
                    b.iter(|| {
                        prove_tf::<_, E, TestComScheme, TestComSchemeG, TestTreeH, TestTreeHG>(
                            &mut rng,
                            &tf_pk,
                            &*MERKLE_CRH_PARAM,
                            &roots,
                            &auth_path,
                            person_com,
                        )
                        .unwrap()
                    })
                },
            );
            let proof = prove_tf::<_, E, TestComScheme, TestComSchemeG, TestTreeH, TestTreeHG>(
                &mut rng,
                &tf_pk,
                &*MERKLE_CRH_PARAM,
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
                        assert!(
                            verify_tf::<E, TestComScheme, TestComSchemeG, TestTreeH, TestTreeHG>(
                                &tf_pvk, &roots, &proof,
                            )
                            .unwrap()
                        )
                    })
                },
            );
        }
    }
}
