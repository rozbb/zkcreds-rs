use ark_crypto_primitives::{
    merkle_tree::{Config, LeafParam, MerkleTree, TwoToOneDigest, TwoToOneParam},
    Error as ArkError,
};
use ark_ff::ToBytes;

/// A collection of Merkle trees
///
/// Invariant: All trees in this forest have the same height
pub struct MerkleForest<P: Config> {
    trees: Vec<MerkleTree<P>>,
}

impl<P: Config> MerkleForest<P> {
    /// Creates a new forest. Requirements: `leaves.len()` must equal `num_trees * 2^k` for some k.
    pub fn new<L: ToBytes>(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        leaves: &[L],
        num_trees: usize,
    ) -> Result<MerkleForest<P>, ArkError> {
        assert!(num_trees > 0, "num_trees should be nonzero");
        assert!(
            leaves.len() % num_trees == 0,
            "leaves.len() should divide num_trees"
        );

        let num_leaves_per_tree = leaves.len() / num_trees;
        assert!(
            num_leaves_per_tree.is_power_of_two(),
            "leaves.len() / num_trees should be a power of two"
        );

        let trees: Result<Vec<MerkleTree<P>>, ArkError> = leaves
            .chunks(num_leaves_per_tree)
            .map(|tree_leaves| {
                MerkleTree::<P>::new(leaf_hash_param, two_to_one_hash_param, tree_leaves)
            })
            .collect();

        Ok(MerkleForest { trees: trees? })
    }

    /// Returns the roots of the trees in the forest
    pub fn roots(&self) -> Vec<TwoToOneDigest<P>> {
        self.trees.iter().map(|t| t.root()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_crypto_primitives::crh::{pedersen, *};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_std::rand::Rng;

    #[derive(Clone)]
    pub(super) struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type Leaf = [u8; 8];

    type H = pedersen::CRH<JubJub, Window4x256>;
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }
    type JubJubMerkleForest = MerkleForest<JubJubMerkleTreeParams>;

    #[test]
    fn merkle_tree_test() {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <H as TwoToOneCRH>::setup(&mut rng).unwrap();

        let num_trees = 5;
        let num_leaves = num_trees * 2usize.pow(8);

        let leaves: Vec<Leaf> = (0..num_leaves).map(|_| rng.gen()).collect();

        let forest = JubJubMerkleForest::new(
            &leaf_crh_params.clone(),
            &two_to_one_crh_params.clone(),
            &leaves,
            num_trees,
        )
        .unwrap();
        let roots = forest.roots();

        println!("Forest roots: {:?}", roots);
    }
}
