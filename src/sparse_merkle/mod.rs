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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    io::{Read, Write},
    string::ToString,
    vec::Vec,
};

/// Constraints for the Merkle sparse tree
pub mod constraints;

pub(crate) type LeafDigest<P> = <<P as TreeConfig>::LeafHash as CRH>::Output;
pub(crate) type TwoToOneDigest<P> = <<P as TreeConfig>::TwoToOneHash as TwoToOneCRH>::Output;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SparseMerkleTreePath<P: TreeConfig> {
    pub(crate) leaf_hashes: (LeafDigest<P>, LeafDigest<P>),
    pub(crate) inner_hashes: Vec<(TwoToOneDigest<P>, TwoToOneDigest<P>)>,
    pub(crate) root: TwoToOneDigest<P>,
}

impl<P: TreeConfig> Clone for SparseMerkleTreePath<P> {
    fn clone(&self) -> Self {
        SparseMerkleTreePath {
            leaf_hashes: self.leaf_hashes.clone(),
            inner_hashes: self.inner_hashes.clone(),
            root: self.root.clone(),
        }
    }
}

impl<P> Default for SparseMerkleTreePath<P>
where
    P: TreeConfig,
{
    fn default() -> SparseMerkleTreePath<P> {
        SparseMerkleTreePath {
            leaf_hashes: (LeafDigest::<P>::default(), LeafDigest::<P>::default()),
            inner_hashes: Vec::default(),
            root: TwoToOneDigest::<P>::default(),
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

    /// Returns the height of the tree that this auth path belongs to
    pub fn height(&self) -> u32 {
        (self.inner_hashes.len() + 2).try_into().unwrap()
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct EmptyHashes<P: TreeConfig> {
    leaf_hash: LeafDigest<P>,
    inner_hashes: Vec<TwoToOneDigest<P>>,
}

impl<P: TreeConfig> Clone for EmptyHashes<P> {
    fn clone(&self) -> Self {
        EmptyHashes {
            leaf_hash: self.leaf_hash.clone(),
            inner_hashes: self.inner_hashes.clone(),
        }
    }
}

/// Merkle sparse tree
pub struct SparseMerkleTree<P>
where
    P: TreeConfig,
    TwoToOneDigest<P>: Eq,
{
    // Tree params
    pub(crate) leaf_param: LeafParam<P>,
    pub(crate) two_to_one_param: TwoToOneParam<P>,
    pub(crate) height: u32,
    // Tree contents
    pub(crate) leaf_hashes: BTreeMap<u64, LeafDigest<P>>,
    pub(crate) inner_hashes: BTreeMap<u64, TwoToOneDigest<P>>,
    // Cached empty hashes
    pub(crate) empty_hashes: EmptyHashes<P>,
}

/// We can't serialize CRH parameters, so the merkle tree wire format is all but the params
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SparseMerkleTreeWireFormat<P>
where
    P: TreeConfig,
    TwoToOneDigest<P>: Eq,
{
    pub(crate) height: u32,
    pub(crate) leaf_hashes: BTreeMap<u64, LeafDigest<P>>,
    pub(crate) inner_hashes: BTreeMap<u64, TwoToOneDigest<P>>,
    pub(crate) empty_hashes: EmptyHashes<P>,
}

impl<P> SparseMerkleTreeWireFormat<P>
where
    P: TreeConfig,
    TwoToOneDigest<P>: Eq,
{
    /// Converts thsi deserialized tree to a full `SparseMerkleTree` by providing the hashing
    /// parameters
    pub fn into_sparse_merkle_tree(
        self,
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
    ) -> SparseMerkleTree<P> {
        SparseMerkleTree {
            leaf_param,
            two_to_one_param,
            height: self.height,
            leaf_hashes: self.leaf_hashes,
            inner_hashes: self.inner_hashes,
            empty_hashes: self.empty_hashes,
        }
    }
}

impl<P> SparseMerkleTree<P>
where
    P: TreeConfig,
    TwoToOneDigest<P>: Eq,
{
    /// Converts this merkle tree to something that can be serialized
    pub fn into_wire_format(&self) -> SparseMerkleTreeWireFormat<P> {
        SparseMerkleTreeWireFormat {
            height: self.height,
            leaf_hashes: self.leaf_hashes.clone(),
            inner_hashes: self.inner_hashes.clone(),
            empty_hashes: self.empty_hashes.clone(),
        }
    }

    /// Obtain an empty tree of a given height. Height MUST be at least 2.
    pub fn empty<L: Default + ToBytes>(
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
                P::TwoToOneHash::evaluate(two_to_one_param, &left_hash_bytes, &right_hash_bytes)?;

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
                    two_to_one_param,
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
        let first_level_idx: u64 = convert_idx_to_last_level(0, height);
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

    /// Generate a membership proof (does not check the leaf value)
    fn generate_proof_helper(&self, index: u64) -> Result<SparseMerkleTreePath<P>, Error> {
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

        // Calculate the root
        let (final_left_hash, final_right_hash) = match path.inner_hashes.last() {
            Some((l, r)) => (to_bytes!(l), to_bytes!(r)),
            None => (to_bytes!(path.leaf_hashes.0), to_bytes!(path.leaf_hashes.0)),
        };
        path.root = P::TwoToOneHash::evaluate(
            &self.two_to_one_param,
            &final_left_hash?,
            &final_right_hash?,
        )?;

        if path.height() != self.height {
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
                return Err(SparseMerkleTreeError::IncorrectTreeStructure.into());
            }
        }

        self.generate_proof_helper(index)
    }

    /// Recomputes the path-to-root starting at the given leaf index
    fn recalculate_leaf_ancestors(&mut self, idx: u64) -> Result<(), Error> {
        // Get the starting two indices
        let leaf_node = convert_idx_to_last_level(idx, self.height);
        let sibling_node = sibling(leaf_node).unwrap();

        // Get the leaf and sibling data and decide whether it's left or right
        let leaf_hash = self
            .leaf_hashes
            .get(&leaf_node)
            .unwrap_or(&self.empty_hashes.leaf_hash)
            .clone();
        let sibling_leaf_hash = self
            .leaf_hashes
            .get(&sibling_node)
            .unwrap_or(&self.empty_hashes.leaf_hash)
            .clone();
        let (left_hash, right_hash) = if is_left_child(leaf_node) {
            (leaf_hash, sibling_leaf_hash)
        } else {
            (sibling_leaf_hash, leaf_hash)
        };

        // Compute the leaf's parent hash and save it
        let leaf_parent_node = parent(leaf_node).unwrap();
        let leaf_parent_hash = P::TwoToOneHash::evaluate(
            &self.two_to_one_param,
            &to_bytes!(left_hash)?,
            &to_bytes!(right_hash)?,
        )?;
        self.inner_hashes.insert(leaf_parent_node, leaf_parent_hash);

        // Iterate from the leaf's parents up to the root, storing all intermediate hash values.
        let mut current_node = leaf_parent_node;
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

            // Compute the hash of this node and its sibling and store it
            let (left_hash, right_hash) = if is_left_child(current_node) {
                (current_hash.clone(), sibling_hash.clone())
            } else {
                (sibling_hash.clone(), current_hash.clone())
            };
            let parent_node = parent(current_node).unwrap();
            let parent_hash = P::TwoToOneHash::evaluate(
                &self.two_to_one_param,
                &to_bytes!(left_hash)?,
                &to_bytes!(right_hash)?,
            )?;
            self.inner_hashes.insert(parent_node, parent_hash);

            // Go up one level
            current_node = parent_node;
        }

        Ok(())
    }

    /// Inserts a leaf into the tree at index `idx`
    pub fn insert<L: ToBytes>(&mut self, idx: u64, leaf: &L) -> Result<(), Error> {
        // Compute the leaf's tree index and insert it into the leaf_hashes map
        let leaf_node = convert_idx_to_last_level(idx, self.height);
        let leaf_hash = P::LeafHash::evaluate(&self.leaf_param, &to_bytes!(leaf)?)?;
        self.leaf_hashes.insert(leaf_node, leaf_hash);

        // Recompute all the nodes above the leaf
        self.recalculate_leaf_ancestors(idx)
    }

    /// Removes a leaf from the tree. Does nothing if there was nothing at that index.
    pub fn remove(&mut self, idx: u64) -> Result<(), Error> {
        let leaf_node = convert_idx_to_last_level(idx, self.height);

        // Try to remove the leaf hash. If there was nothing to remove, do nothing. Otherwise,
        // recompute the hashes upwards, starting at the removed leaf hash.
        match self.leaf_hashes.remove(&leaf_node) {
            None => Ok(()),
            Some(_) => self.recalculate_leaf_ancestors(idx),
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
fn convert_idx_to_last_level(idx: u64, tree_height: u32) -> u64 {
    // A tree of height n has 2^(n-1) leaves
    assert!(idx < 2u64.pow(tree_height - 1), "idx exceeds capacity");
    idx + 2u64.pow(tree_height - 1) - 1
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
        P::LeafHash::evaluate(leaf_param, &empty_leaf_bytes)?
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

    /// Check if the tree is structurally valid
    fn validate_tree<P: TreeConfig>(tree: &SparseMerkleTree<P>) -> Result<bool, Error> {
        // If this tree is empty, then it's valid by default. Otherwise, recalculate the root and
        // compare it to
        if tree.is_empty() {
            Ok(true)
        } else {
            let expected_root = tree.root();
            let calculated_root = SparseMerkleTree::calculate_inner_hashes(
                &tree.two_to_one_param,
                tree.height,
                &tree.leaf_hashes,
                &tree.empty_hashes,
                true,
            )?
            .get(&0)
            .cloned()
            .unwrap();

            Ok(expected_root == calculated_root)
        }
    }

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
        assert!(validate_tree(&tree).unwrap());

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

    // Test insertion and removal on an existing tree
    #[test]
    fn test_insert_remove() {
        let mut rng = ark_std::test_rng();
        let num_leaves = 50;

        // Setup hashing params
        let leaf_param = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_param = <H as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Make an empty tree
        /*
        let mut tree =
            JubJubMerkleTree::empty::<Leaf>(leaf_param.clone(), two_to_one_param.clone(), HEIGHT);
        */
        let mut tree = JubJubMerkleTree::new::<Leaf>(
            leaf_param.clone(),
            two_to_one_param.clone(),
            HEIGHT,
            &BTreeMap::new(),
        )
        .unwrap();

        // Iteratively insert leaves into the tree
        let mut leaves: BTreeMap<u64, Leaf> = BTreeMap::new();
        for i in 0..num_leaves {
            let mut leaf = Leaf::default();
            rng.fill_bytes(&mut leaf);

            // Insert into the tree and also store in `leaves`
            tree.insert(i as u64, &leaf).unwrap();
            leaves.insert(i as u64, leaf);
        }

        // Validate the whole tree
        assert!(validate_tree(&tree).unwrap());

        // Generate proofs and verify that they're valid
        let root = tree.root();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof
                .verify(&leaf_param, &two_to_one_param, &root, &leaf)
                .unwrap());
        }

        // Remove a leaf and check that the old proof doesn't verify wrt the new root
        let remove_idx = 1;
        let removed_leaf = leaves.get(&remove_idx).unwrap();
        let old_proof = tree.generate_proof(remove_idx, removed_leaf).unwrap();
        tree.remove(remove_idx).unwrap();
        let root = tree.root();
        assert!(!old_proof
            .verify(&leaf_param, &two_to_one_param, &root, &removed_leaf,)
            .unwrap());

        // Insert a new leaf in the same spot and make a valid proof
        let insert_idx = remove_idx;
        let inserted_leaf = {
            let mut buf = Leaf::default();
            rng.fill_bytes(&mut buf);
            buf
        };
        tree.insert(insert_idx, &inserted_leaf).unwrap();
        let new_proof = tree.generate_proof(insert_idx, &inserted_leaf).unwrap();
        let root = tree.root();
        assert!(new_proof
            .verify(&leaf_param, &two_to_one_param, &root, &inserted_leaf,)
            .unwrap());

        // Validate the whole tree again
        assert!(validate_tree(&tree).unwrap());
    }
}
