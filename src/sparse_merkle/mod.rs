// This file was copied and modified from
// https://github.com/arkworks-rs/ivls/blob/57325dc45db4f1b5d42bed4796cd9ba2cd1fbd3c/src/building_blocks/mt/merkle_sparse_tree/mod.rs
// under dual MIT/APACHE license.

use crate::Error;

use core::convert::{TryFrom, TryInto};

use ark_crypto_primitives::{
    crh::{TwoToOneCRH, CRH},
    merkle_tree::{Config as TreeConfig, LeafParam, TwoToOneParam},
};
use ark_ff::{to_bytes, ToBytes};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    string::ToString,
    vec::Vec,
};

/// Constraints for the Merkle sparse tree
pub mod constraints;

type LeafDigest<P> = <<P as TreeConfig>::LeafHash as CRH>::Output;
type TwoToOneDigest<P> = <<P as TreeConfig>::TwoToOneHash as TwoToOneCRH>::Output;

pub struct SparseMerkleTreePath<P: TreeConfig> {
    pub(crate) leaf_hashes: (LeafDigest<P>, LeafDigest<P>),
    pub(crate) inner_hashes: Vec<(TwoToOneDigest<P>, TwoToOneDigest<P>)>,
}

impl<P> Default for SparseMerkleTreePath<P>
where
    P: TreeConfig,
{
    fn default() -> SparseMerkleTreePath<P> {
        SparseMerkleTreePath {
            leaf_hashes: (LeafDigest::<P>::default(), LeafDigest::<P>::default()),
            inner_hashes: vec![],
        }
    }
}

impl<P> SparseMerkleTreePath<P>
where
    P: TreeConfig,
    TwoToOneDigest<P>: Eq,
{
    // TODO: Make this constant time if you want to store secrets in the Merkle tree
    /// Verify the lookup proof, just checking the membership
    pub fn verify<L: ToBytes>(
        &self,
        leaf_param: &LeafParam<P>,
        two_to_one_param: &TwoToOneParam<P>,
        root_hash: &TwoToOneDigest<P>,
        leaf: &L,
    ) -> Result<bool, Error> {
        // Check that the given leaf matches the leaf in the membership proof.
        let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_param, &to_bytes!(leaf)?)?;

        if claimed_leaf_hash != self.leaf_hashes.0 && claimed_leaf_hash != self.leaf_hashes.1 {
            return Ok(false);
        }

        // Check levels between leaf level and root
        let mut previous_hash = P::TwoToOneHash::evaluate(
            &two_to_one_param,
            &to_bytes!(self.leaf_hashes.0)?,
            &to_bytes!(self.leaf_hashes.1)?,
        )?;
        for (ref left_hash, ref right_hash) in &self.inner_hashes {
            // Check if the previous hash matches the correct current hash.
            if &previous_hash != left_hash && &previous_hash != right_hash {
                return Ok(false);
            }
            previous_hash = P::TwoToOneHash::evaluate(
                &two_to_one_param,
                &to_bytes!(left_hash)?,
                &to_bytes!(right_hash)?,
            )?;
        }

        Ok(root_hash == &previous_hash)
    }
}
/*

    /// verify the lookup proof, given the location
    pub fn verify_with_idx<L: ToBytes>(
        &self,
        parameters: &<P::H as CRH>::Parameters,
        root_hash: &<P::H as CRH>::Output,
        leaf: &L,
        index: u64,
    ) -> Result<bool, Error> {
        if self.path.len() != (P::HEIGHT - 1) as usize {
            return Ok(false);
        }
        // Check that the given leaf matches the leaf in the membership proof.
        let first_level_idx: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        let tree_idx: u64 = first_level_idx + index;

        let mut index_from_path: u64 = first_level_idx;
        let mut index_offset: u64 = 1;

        if !self.path.is_empty() {
            let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

            if tree_idx % 2 == 1 {
                if claimed_leaf_hash != self.path[0].0 {
                    return Ok(false);
                }
            } else if claimed_leaf_hash != self.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            let mut prev_idx = tree_idx;
            // Check levels between leaf level and root.
            for &(ref left_hash, ref right_hash) in &self.path {
                // Check if the previous hash matches the correct current hash.
                if prev_idx % 2 == 1 {
                    if &prev != left_hash {
                        return Ok(false);
                    }
                } else {
                    if &prev != right_hash {
                        return Ok(false);
                    }
                    index_from_path += index_offset;
                }
                index_offset *= 2;
                prev_idx = (prev_idx - 1) / 2;
                prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
            }

            if root_hash != &prev {
                return Ok(false);
            }

            if index_from_path != tree_idx {
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }
}
*/

/// Merkle sparse tree
pub struct SparseMerkleTree<P>
where
    P: TreeConfig,
    TwoToOneDigest<P>: Eq,
{
    // Tree params
    leaf_param: LeafParam<P>,
    two_to_one_param: TwoToOneParam<P>,
    height: u32,
    // Tree contents
    leaf_hashes: BTreeMap<u64, LeafDigest<P>>,
    inner_hashes: BTreeMap<u64, TwoToOneDigest<P>>,
    // Cached empty hashes
    empty_hashes: EmptyHashes<P>,
}

struct EmptyHashes<P: TreeConfig> {
    leaf_hash: LeafDigest<P>,
    inner_hashes: Vec<TwoToOneDigest<P>>,
}

impl<P> SparseMerkleTree<P>
where
    P: TreeConfig,
    TwoToOneDigest<P>: Eq,
{
    /// Obtain an empty tree of a given height. Height MUST be at least 2.
    pub fn blank<L: Default + ToBytes>(
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
        height: u32,
    ) -> Self {
        assert!(height >= 2, "Tree height must be at least 2");

        let empty_hashes =
            gen_empty_hashes::<P, L>(&leaf_param, &two_to_one_param, height).unwrap();

        SparseMerkleTree {
            leaf_param,
            two_to_one_param,
            height,
            leaf_hashes: BTreeMap::new(),
            inner_hashes: BTreeMap::new(),
            empty_hashes,
        }
    }

    /// Given leaf hashes, does the rest of the computations to fill out the tree. If `root_only`
    /// is true, then this will return just the root value at index 0 of the `BTreeMap`. Otherwise
    /// it will return the full inner tree.
    fn calculate_inner_hashes(
        two_to_one_param: &TwoToOneParam<P>,
        height: u32,
        leaf_hashes: &BTreeMap<u64, LeafDigest<P>>,
        empty_hashes: &EmptyHashes<P>,
        root_only: bool,
    ) -> Result<BTreeMap<u64, TwoToOneDigest<P>>, Error> {
        // Calculate the indices of the leaf parents
        let leaf_parents: BTreeSet<u64> = leaf_hashes.keys().map(|&i| parent(i).unwrap()).collect();

        // Construct the hashes for all the leaf parents
        let mut inner_hashes: BTreeMap<u64, TwoToOneDigest<P>> = BTreeMap::new();
        for &parent_idx in leaf_parents.iter() {
            let left_idx = left_child(parent_idx);
            let right_idx = right_child(parent_idx);

            let left_hash = leaf_hashes
                .get(&left_idx)
                .unwrap_or(&empty_hashes.leaf_hash);
            let right_hash = leaf_hashes
                .get(&right_idx)
                .unwrap_or(&empty_hashes.leaf_hash);

            // Compute H(left || right).
            let left_hash_bytes = to_bytes![left_hash]?;
            let right_hash_bytes = to_bytes![right_hash]?;
            let hash =
                P::TwoToOneHash::evaluate(&two_to_one_param, &left_hash_bytes, &right_hash_bytes)?;

            // Insert the digest
            inner_hashes.insert(parent_idx, hash);
        }

        // Now compute the parents of all the leaf parents
        let mut inner_nodes = BTreeSet::new();
        for i in leaf_parents {
            if !is_root(i) {
                inner_nodes.insert(parent(i).unwrap());
            }
        }

        // Compute the hash values for every remaining node with a non-null child
        for level in 1..height {
            let level: usize = level.try_into().unwrap();

            // Iterate over the current level.
            for &current_idx in &inner_nodes {
                let left_idx = left_child(current_idx);
                let right_idx = right_child(current_idx);

                let left_hash = inner_hashes
                    .get(&left_idx)
                    .unwrap_or(&empty_hashes.inner_hashes[level - 1]);
                let right_hash = inner_hashes
                    .get(&right_idx)
                    .unwrap_or(&empty_hashes.inner_hashes[level - 1]);

                // Compute H(left || right).
                let left_hash_bytes = to_bytes![left_hash]?;
                let right_hash_bytes = to_bytes![right_hash]?;
                let hash = P::TwoToOneHash::evaluate(
                    &two_to_one_param,
                    &left_hash_bytes,
                    &right_hash_bytes,
                )?;

                // Insert the digest
                inner_hashes.insert(current_idx, hash);

                // If root_only is selected, we don't have to keep the child hashes
                if root_only {
                    inner_hashes.remove(&left_idx);
                    inner_hashes.remove(&right_idx);
                }
            }

            // Make the next iteration all the parents of the nodes in this level
            let tmp_inner_nodes = inner_nodes.clone();
            inner_nodes.clear();
            for i in tmp_inner_nodes {
                if !is_root(i) {
                    inner_nodes.insert(parent(i).unwrap());
                }
            }
        }

        Ok(inner_hashes)
    }

    /// Initialize a tree with optional data. Tree height MUST be at least 2.
    pub fn new<L: Default + ToBytes>(
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
        height: u32,
        leaves: &BTreeMap<u64, L>,
    ) -> Result<Self, Error> {
        assert!(height >= 2, "Tree height must be at least 2");

        let min_height = {
            let last_level_size = leaves.len().next_power_of_two();
            let tree_size = 2 * last_level_size - 1;
            tree_height(tree_size as u64)
        };
        assert!(min_height <= height.try_into().unwrap());

        // Get empty hashes
        let empty_hashes =
            gen_empty_hashes::<P, L>(&leaf_param, &two_to_one_param, height).unwrap();

        // Compute and store the hash values for each leaf.
        let mut leaf_hashes: BTreeMap<u64, LeafDigest<P>> = BTreeMap::new();
        let first_level_idx: u64 = 2u64.pow(height - 1) - 1;
        for (&i, leaf) in leaves.iter() {
            let leaf_bytes = to_bytes!(leaf)?;
            let leaf_hash = P::LeafHash::evaluate(&leaf_param, &leaf_bytes)?;

            leaf_hashes.insert(first_level_idx + i, leaf_hash);
        }

        // Calculate the rest of the tree
        let inner_hashes = Self::calculate_inner_hashes(
            &two_to_one_param,
            height,
            &leaf_hashes,
            &empty_hashes,
            false,
        )?;

        Ok(SparseMerkleTree {
            leaf_param,
            two_to_one_param,
            height,
            leaf_hashes,
            inner_hashes,
            empty_hashes,
        })
    }

    /// Obtain the root hash
    #[inline]
    pub fn root(&self) -> TwoToOneDigest<P> {
        // If this tree is completely empty, then the root hash is the last empty hash. Otherwise,
        // it's the root node of inner_hashes
        if self.is_empty() {
            self.empty_hashes.inner_hashes.last().cloned().unwrap()
        } else {
            self.inner_hashes.get(&0).cloned().unwrap()
        }
    }

    /// Returns true if no leaves were ever inserted into this tree
    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    /// generate a membership proof (does not check the data point)
    pub fn generate_membership_proof(&self, index: u64) -> Result<SparseMerkleTreePath<P>, Error> {
        let mut path = SparseMerkleTreePath::default();

        let mut current_node = convert_idx_to_last_level(index, self.height);

        // Get the leaf hashes
        let sibling_node = sibling(current_node).unwrap();
        let my_leaf_hash = self
            .leaf_hashes
            .get(&current_node)
            .unwrap_or(&self.empty_hashes.leaf_hash);
        let sibling_leaf_hash = self
            .leaf_hashes
            .get(&sibling_node)
            .unwrap_or(&self.empty_hashes.leaf_hash);

        // Store the leaf hashes in the correct order
        if is_left_child(current_node) {
            path.leaf_hashes = (my_leaf_hash.clone(), sibling_leaf_hash.clone());
        } else {
            path.leaf_hashes = (sibling_leaf_hash.clone(), my_leaf_hash.clone());
        }

        // Push up one level
        current_node = parent(current_node).unwrap();

        // Iterate from the leaf's parents up to the root, storing all intermediate hash values.
        let mut empty_hash_iter = self.empty_hashes.inner_hashes.iter();
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();

            // The empty hash corresponding to this level in the tree
            let level_empty_hash = empty_hash_iter.next().unwrap();

            // Get the hashes of the current node and its sibling
            let current_hash = self
                .inner_hashes
                .get(&current_node)
                .unwrap_or(level_empty_hash);
            let sibling_hash = self
                .inner_hashes
                .get(&sibling_node)
                .unwrap_or(level_empty_hash);

            // Store the hashes in the correct order
            if is_left_child(current_node) {
                path.inner_hashes
                    .push((current_hash.clone(), sibling_hash.clone()));
            } else {
                path.inner_hashes
                    .push((sibling_hash.clone(), current_hash.clone()));
            }
            current_node = parent(current_node).unwrap();
        }

        if path.inner_hashes.len() != (self.height - 2) as usize {
            Err(SparseMerkleTreeError::IncorrectPathLength(path.inner_hashes.len()).into())
        } else {
            Ok(path)
        }
    }

    /// Generates a lookup proof. Errors when the given leaf is not found at the given index.
    pub fn generate_proof<L: ToBytes>(
        &self,
        index: u64,
        leaf: &L,
    ) -> Result<SparseMerkleTreePath<P>, Error> {
        let leaf_hash = P::LeafHash::evaluate(&self.leaf_param, &to_bytes!(leaf)?)?;
        let tree_idx = convert_idx_to_last_level(index, self.height);

        // Check that the given index corresponds to the correct leaf.
        if let Some(x) = self.leaf_hashes.get(&tree_idx) {
            if &leaf_hash != x {
                Err(SparseMerkleTreeError::IncorrectTreeStructure)?;
            }
        }

        self.generate_membership_proof(index)
    }

    /// Check if the tree is structurally valid
    pub fn validate(&self) -> Result<bool, Error> {
        // If this tree is empty, then it's valid by default. Otherwise, recalculate the root and
        // compare it to
        if self.is_empty() {
            Ok(true)
        } else {
            let expected_root = self.root();
            let calculated_root = Self::calculate_inner_hashes(
                &self.two_to_one_param,
                self.height,
                &self.leaf_hashes,
                &self.empty_hashes,
                true,
            )?
            .get(&0)
            .cloned()
            .unwrap();

            Ok(expected_root == calculated_root)
        }
    }
}

/// error for Merkle sparse tree
#[derive(Debug)]
pub enum SparseMerkleTreeError {
    /// the path's length does not work for this tree
    IncorrectPathLength(usize),
    /// Tree structure is incorrect, some nodes are missing
    IncorrectTreeStructure,
}

impl core::fmt::Display for SparseMerkleTreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            SparseMerkleTreeError::IncorrectPathLength(len) => {
                format!("incorrect path length: {}", len)
            }
            SparseMerkleTreeError::IncorrectTreeStructure => "incorrect tree structure".to_string(),
        };
        write!(f, "{}", msg)
    }
}

impl ark_std::error::Error for SparseMerkleTreeError {}

/// Returns the log2 value of the given number.
#[inline]
fn log2(number: u64) -> u64 {
    ark_std::log2(number as usize) as u64
}

/// Returns the height of the tree, given the size of the tree.
#[inline]
fn tree_height(tree_size: u64) -> u64 {
    log2(tree_size)
}

/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: u64) -> bool {
    index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: u64) -> u64 {
    2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: u64) -> u64 {
    2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: u64) -> Option<u64> {
    if index == 0 {
        None
    } else if is_left_child(index) {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: u64) -> bool {
    index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: u64) -> Option<u64> {
    if index > 0 {
        Some((index - 1) >> 1)
    } else {
        None
    }
}

#[inline]
fn convert_idx_to_last_level(index: u64, tree_height: u32) -> u64 {
    index + 2u64.pow(tree_height - 1) - 1
}

/// Returns the digests H(nil), H(H(nil), H(nil)), etc.
fn gen_empty_hashes<P: TreeConfig, L: ToBytes + Default>(
    leaf_param: &LeafParam<P>,
    two_to_one_param: &TwoToOneParam<P>,
    height: u32,
) -> Result<EmptyHashes<P>, Error> {
    assert!(height >= 2);

    let empty_leaf_hash = {
        let empty_leaf_bytes = to_bytes!(L::default())?;
        P::LeafHash::evaluate(&leaf_param, &empty_leaf_bytes)?
    };

    let mut empty_inner_hashes = Vec::with_capacity(usize::try_from(height).unwrap() - 1);
    let mut running_inner_hash = {
        let empty_leaf_hash_bytes = to_bytes!(empty_leaf_hash)?;
        P::TwoToOneHash::evaluate(
            two_to_one_param,
            &empty_leaf_hash_bytes,
            &empty_leaf_hash_bytes,
        )?
    };
    empty_inner_hashes.push(running_inner_hash.clone());

    // Compute v := H(v, v) iteratively, storing intermediate results
    for _ in 1..=height {
        let running_bytes = to_bytes![running_inner_hash]?;
        running_inner_hash =
            P::TwoToOneHash::evaluate(two_to_one_param, &running_bytes, &running_bytes)?;
        empty_inner_hashes.push(running_inner_hash.clone());
    }

    Ok(EmptyHashes {
        leaf_hash: empty_leaf_hash,
        inner_hashes: empty_inner_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_crypto_primitives::{
        crh::{bowe_hopwood, pedersen},
        merkle_tree::Config,
    };
    use ark_ed_on_bls12_381::EdwardsParameters;
    use ark_std::rand::RngCore;

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63;
        const NUM_WINDOWS: usize = 9;
    }

    #[derive(Clone)]
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }

    type JubJubMerkleTree = SparseMerkleTree<JubJubMerkleTreeParams>;
    type H = bowe_hopwood::CRH<EdwardsParameters, Window>;

    type Leaf = [u8; 8];
    const HEIGHT: u32 = 32;

    #[test]
    fn test_membership() {
        let mut rng = ark_std::test_rng();
        let num_leaves = 5;

        // Setup hashing params
        let leaf_param = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_param = <H as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Construct a tree of size 4
        let mut leaves: BTreeMap<u64, Leaf> = BTreeMap::new();
        for i in 0..num_leaves {
            let mut leaf = Leaf::default();
            rng.fill_bytes(&mut leaf);
            leaves.insert(i as u64, leaf);
        }
        let tree = JubJubMerkleTree::new(
            leaf_param.clone(),
            two_to_one_param.clone(),
            HEIGHT,
            &leaves,
        )
        .unwrap();

        // Validate the whole tree
        assert!(tree.validate().unwrap());

        // Generate proofs and verify that they're valid
        let root = tree.root();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof
                .verify(&leaf_param, &two_to_one_param, &root, &leaf)
                .unwrap());
        }

        // Now generate proofs and verify that they don't validate under an incorrect root
        let root = TwoToOneDigest::<JubJubMerkleTreeParams>::default();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(!proof
                .verify(&leaf_param, &two_to_one_param, &root, &leaf)
                .unwrap());
        }
    }
}

/*
#[cfg(test)]
mod test {
    use crate::building_blocks::mt::merkle_sparse_tree::*;

    use ark_ed_on_bls12_381::Fr;
    use ark_ff::{ToBytes, Zero};

    use crate::building_blocks::crh::poseidon::PoseidonCRH;
    use ark_std::collections::BTreeMap;
    use rand_chacha::ChaChaRng;

    type H = PoseidonCRH<ChaChaRng, Fr>;

    #[derive(Debug)]
    struct JubJubMerkleTreeParams;

    impl TreeConfig for JubJubMerkleTreeParams {
        const HEIGHT: u64 = 32;
        type H = H;
    }
    type JubJubMerkleTree = SparseMerkleTree<JubJubMerkleTreeParams>;

    fn generate_merkle_tree_and_test_membership<L: Default + ToBytes + Clone + Eq>(
        leaves: &BTreeMap<u64, L>,
    ) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), leaves).unwrap();
        let root = tree.root();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof.verify(&crh_parameters, &root, &leaf).unwrap());
            assert!(proof
                .verify_with_idx(&crh_parameters, &root, &leaf, *i)
                .unwrap());
        }

        assert!(tree.validate().unwrap());
    }

    #[test]
    fn good_root_membership_test() {
        let mut leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..4u8 {
            leaves.insert(i as u64, i);
        }
        generate_merkle_tree_and_test_membership(&leaves);
        let mut leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..100u8 {
            leaves.insert(i as u64, i);
        }
        generate_merkle_tree_and_test_membership(&leaves);
    }

    fn generate_merkle_tree_with_bad_root_and_test_membership<L: Default + ToBytes + Clone + Eq>(
        leaves: &BTreeMap<u64, L>,
    ) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), leaves).unwrap();
        let root = Fr::zero();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof.verify(&crh_parameters, &root, &leaf).unwrap());
            assert!(proof
                .verify_with_idx(&crh_parameters, &root, &leaf, *i)
                .unwrap());
        }
    }

    #[should_panic]
    #[test]
    fn bad_root_membership_test() {
        let mut leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..100u8 {
            leaves.insert(i as u64, i);
        }
        generate_merkle_tree_with_bad_root_and_test_membership(&leaves);
    }

    fn generate_merkle_tree_and_test_update<L: Default + ToBytes + Clone + Eq>(
        old_leaves: &BTreeMap<u64, L>,
        new_leaves: &BTreeMap<u64, L>,
    ) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(crh_parameters.clone(), old_leaves).unwrap();
        for (i, new_leaf) in new_leaves.iter() {
            let old_root = tree.root.unwrap();
            let old_leaf_option = old_leaves.get(i);

            match old_leaf_option {
                Some(old_leaf) => {
                    let old_leaf_membership_proof = tree.generate_proof(*i, &old_leaf).unwrap();
                    let update_proof = tree.update_and_prove(*i, &new_leaf).unwrap();
                    let new_leaf_membership_proof = tree.generate_proof(*i, &new_leaf).unwrap();
                    let new_root = tree.root.unwrap();

                    assert!(old_leaf_membership_proof
                        .verify_with_idx(&crh_parameters, &old_root, &old_leaf, *i)
                        .unwrap());
                    assert!(
                        !(old_leaf_membership_proof
                            .verify_with_idx(&crh_parameters, &new_root, &old_leaf, *i)
                            .unwrap())
                    );
                    assert!(new_leaf_membership_proof
                        .verify_with_idx(&crh_parameters, &new_root, &new_leaf, *i)
                        .unwrap());
                    assert!(
                        !(new_leaf_membership_proof
                            .verify_with_idx(&crh_parameters, &new_root, &old_leaf, *i)
                            .unwrap())
                    );

                    assert!(update_proof
                        .verify(&crh_parameters, &old_root, &new_root, &new_leaf, *i)
                        .unwrap());
                }
                None => {
                    let update_proof = tree.update_and_prove(*i, &new_leaf).unwrap();
                    let new_leaf_membership_proof = tree.generate_proof(*i, &new_leaf).unwrap();
                    let new_root = tree.root.unwrap();

                    assert!(new_leaf_membership_proof
                        .verify_with_idx(&crh_parameters, &new_root, &new_leaf, *i)
                        .unwrap());
                    assert!(update_proof
                        .verify(&crh_parameters, &old_root, &new_root, &new_leaf, *i)
                        .unwrap());
                }
            }
        }
    }

    #[test]
    fn good_root_update_test() {
        let mut old_leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..10u8 {
            old_leaves.insert(i as u64, i);
        }
        let mut new_leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..20u8 {
            new_leaves.insert(i as u64, i + 1);
        }
        generate_merkle_tree_and_test_update(&old_leaves, &new_leaves);
    }
}
*/