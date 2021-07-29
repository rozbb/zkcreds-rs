use ark_crypto_primitives::{
    merkle_tree::{Config, LeafParam, MerkleTree, TwoToOneDigest, TwoToOneParam},
    Error as ArkError,
};
use ark_ff::ToBytes;

/// A collection of Merkle trees
///
/// Invariant: All trees in this forest have the same height
pub struct MerkleForest<P: Config> {
    pub trees: Vec<MerkleTree<P>>,
    pub(crate) leaf_crh_param: LeafParam<P>,
    pub(crate) two_to_one_crh_param: TwoToOneParam<P>,
}

impl<P: Config> MerkleForest<P> {
    /// Creates a new forest. Requirements: `leaves.len()` must equal `num_trees * 2^k` for some k.
    pub fn new<L: ToBytes>(
        leaf_crh_param: &LeafParam<P>,
        two_to_one_crh_param: &TwoToOneParam<P>,
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
                MerkleTree::<P>::new(leaf_crh_param, two_to_one_crh_param, tree_leaves)
            })
            .collect();

        Ok(MerkleForest {
            trees: trees?,
            leaf_crh_param: leaf_crh_param.clone(),
            two_to_one_crh_param: two_to_one_crh_param.clone(),
        })
    }

    /// Returns an empty forest
    pub fn empty(
        leaf_crh_param: &LeafParam<P>,
        two_to_one_crh_param: &TwoToOneParam<P>,
    ) -> Result<MerkleForest<P>, ArkError> {
        Ok(MerkleForest {
            trees: Vec::new(),
            leaf_crh_param: leaf_crh_param.clone(),
            two_to_one_crh_param: two_to_one_crh_param.clone(),
        })
    }

    /// Returns the roots of the trees in the forest
    pub fn roots(&self) -> Vec<TwoToOneDigest<P>> {
        self.trees.iter().map(|t| t.root()).collect()
    }
}

impl<P: Config + Clone> Clone for MerkleForest<P> {
    fn clone(&self) -> MerkleForest<P> {
        MerkleForest {
            trees: self.trees.clone(),
            leaf_crh_param: self.leaf_crh_param.clone(),
            two_to_one_crh_param: self.two_to_one_crh_param.clone(),
        }
    }
}

/// Given a leaf index and forest info, return the corresponding tree index leaf-within-tree index
pub fn idx_1d_to_2d(leaf_idx: usize, num_trees: usize, num_leaves: usize) -> (usize, usize) {
    let num_leaves_per_tree = num_leaves / num_trees;

    let tree_idx = leaf_idx / num_leaves_per_tree;
    let leaf_within_tree_idx = leaf_idx % num_leaves_per_tree;

    (tree_idx, leaf_within_tree_idx)
}

/// Re-export of arkworks' Merkle path
pub type Path<P> = ark_crypto_primitives::merkle_tree::Path<P>;

#[cfg(test)]
mod tests {
    use super::*;

    use ark_crypto_primitives::crh::{pedersen, *};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_std::rand::Rng;

    type Leaf = [u8; 8];

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = pedersen::CRH<JubJub, Window>;
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }
    type JubJubMerkleForest = MerkleForest<JubJubMerkleTreeParams>;

    #[test]
    fn merkle_tree_test() {
        let mut rng = ark_std::test_rng();

        // Setup hashing params
        let leaf_crh_params = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <H as TwoToOneCRH>::setup(&mut rng).unwrap();

        // num_trees can be arbitrary, and num_leaves has to be num_trees * 2^k for some k
        let num_trees = 5;
        let num_leaves = num_trees * 2usize.pow(8);

        // Randomly generate the appropriate number of leaves
        let leaves: Vec<Leaf> = (0..num_leaves).map(|_| rng.gen()).collect();

        // Create the forest
        let forest = JubJubMerkleForest::new(
            &leaf_crh_params.clone(),
            &two_to_one_crh_params.clone(),
            &leaves,
            num_trees,
        )
        .unwrap();

        // Make sure we can calculate roots and generate auth paths
        forest.roots();
        forest.trees[2].generate_proof(233).unwrap();
    }
}
