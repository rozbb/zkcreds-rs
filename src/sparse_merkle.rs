// This file was copied and modified from
// https://github.com/arkworks-rs/ivls/blob/57325dc45db4f1b5d42bed4796cd9ba2cd1fbd3c/src/building_blocks/mt/merkle_sparse_tree/mod.rs
// under dual MIT/APACHE license.

use crate::Error;

use core::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

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

/// constraints for the Merkle sparse tree
//pub mod constraints;

pub struct SparseMerkleTreePath<P: TreeConfig> {
    pub(crate) path: Vec<(Vec<u8>, Vec<u8>)>,
    _marker: PhantomData<P>,
}

impl<P> SparseMerkleTreePath<P>
where
    P: TreeConfig,
{
    /// verify the lookup proof, just checking the membership
    pub fn verify<L: ToBytes>(
        &self,
        leaf_param: &LeafParam<P>,
        two_to_one_param: &TwoToOneParam<P>,
        root_hash: &[u8],
        leaf: &L,
    ) -> Result<bool, Error> {
        // Check that the given leaf matches the leaf in the membership proof.
        if !self.path.is_empty() {
            let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_param, &to_bytes!(leaf)?)?;
            let claimed_leaf_hash = to_bytes!(claimed_leaf_hash)?;

            if claimed_leaf_hash != self.path[0].0 && claimed_leaf_hash != self.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            // Check levels between leaf level and root.
            for &(ref left_hash, ref right_hash) in &self.path {
                // Check if the previous hash matches the correct current hash.
                if &prev != left_hash && &prev != right_hash {
                    return Ok(false);
                }
                prev = {
                    let digest =
                        P::TwoToOneHash::evaluate(&two_to_one_param, left_hash, right_hash)?;
                    to_bytes!(digest)?
                };
            }

            if root_hash != &prev {
                return Ok(false);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn height(&self) -> usize {
        self.path.len() + 1
    }
}
/*

    /// verify the lookup proof, given the location
    pub fn verify_with_index<L: ToBytes>(
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
        let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        let tree_index: u64 = last_level_index + index;

        let mut index_from_path: u64 = last_level_index;
        let mut index_offset: u64 = 1;

        if !self.path.is_empty() {
            let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

            if tree_index % 2 == 1 {
                if claimed_leaf_hash != self.path[0].0 {
                    return Ok(false);
                }
            } else if claimed_leaf_hash != self.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            let mut prev_index = tree_index;
            // Check levels between leaf level and root.
            for &(ref left_hash, ref right_hash) in &self.path {
                // Check if the previous hash matches the correct current hash.
                if prev_index % 2 == 1 {
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
                prev_index = (prev_index - 1) / 2;
                prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
            }

            if root_hash != &prev {
                return Ok(false);
            }

            if index_from_path != tree_index {
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
pub struct SparseMerkleTree<P: TreeConfig> {
    /// data of the tree
    height: u64,
    pub tree: BTreeMap<u64, Vec<u8>>,
    leaf_param: LeafParam<P>,
    two_to_one_param: TwoToOneParam<P>,
    root: Option<Vec<u8>>,
    empty_hashes: Vec<Vec<u8>>,
}

impl<P: TreeConfig> SparseMerkleTree<P> {
    /// obtain an empty tree
    pub fn blank<L: Default + ToBytes>(
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
        height: u64,
    ) -> Self {
        let empty_hashes =
            gen_empty_hashes::<P, L>(&leaf_param, &two_to_one_param, height).unwrap();
        let root = empty_hashes[usize::try_from(height - 1).unwrap()].clone();

        SparseMerkleTree {
            height,
            tree: BTreeMap::new(),
            leaf_param,
            two_to_one_param,
            root: Some(root),
            empty_hashes,
        }
    }

    /// initialize a tree (with optional data)
    pub fn new<L: Default + ToBytes>(
        leaf_param: LeafParam<P>,
        two_to_one_param: TwoToOneParam<P>,
        height: u64,
        leaves: &BTreeMap<u64, L>,
    ) -> Result<Self, Error> {
        let last_level_size = leaves.len().next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let min_height = tree_height(tree_size as u64);

        assert!(min_height <= height);

        // Initialize the merkle tree.
        let mut tree: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let empty_hashes =
            gen_empty_hashes::<P, L>(&leaf_param, &two_to_one_param, height).unwrap();

        // Compute and store the hash values for each leaf.
        let last_level_index: u64 = (1u64 << (height - 1)) - 1;
        for (&i, leaf) in leaves.iter() {
            let leaf_bytes = to_bytes!(leaf)?;
            let leaf_hash = P::LeafHash::evaluate(&leaf_param, &leaf_bytes)?;

            tree.insert(last_level_index + i, to_bytes!(leaf_hash)?);
        }

        let mut middle_nodes: BTreeSet<u64> = leaves
            .keys()
            .map(|&i| parent(last_level_index + i).unwrap())
            .collect();

        // Compute the hash values for every node in parts of the tree.
        for level in 0..height {
            let level = usize::try_from(level).unwrap();

            // Iterate over the current level.
            for &current_index in middle_nodes.iter() {
                let left_index = left_child(current_index);
                let right_index = right_child(current_index);

                let mut left_hash = &empty_hashes[level];
                let mut right_hash = &empty_hashes[level];

                if tree.contains_key(&left_index) {
                    match tree.get(&left_index) {
                        Some(x) => left_hash = x,
                        _ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
                    }
                }

                if tree.contains_key(&right_index) {
                    match tree.get(&right_index) {
                        Some(x) => right_hash = x,
                        _ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
                    }
                }

                // Compute Hash(left || right).
                let hash = P::TwoToOneHash::evaluate(&two_to_one_param, &left_hash, &right_hash)?;
                tree.insert(current_index, to_bytes!(hash)?);
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        let root_hash;
        match tree.get(&0) {
            Some(x) => root_hash = (*x).clone(),
            _ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
        }

        Ok(SparseMerkleTree {
            height,
            tree,
            leaf_param,
            two_to_one_param,
            root: Some(root_hash),
            empty_hashes,
        })
    }

    /// obtain the root hash
    #[inline]
    pub fn root(&self) -> Vec<u8> {
        self.root.clone().unwrap()
    }

    /// generate a membership proof (does not check the data point)
    pub fn generate_membership_proof(&self, index: u64) -> Result<SparseMerkleTreePath<P>, Error> {
        let mut path = Vec::new();

        let tree_index = convert_index_to_last_level(index, self.height);

        // Iterate from the leaf up to the root, storing all intermediate hash values.
        let mut current_node = tree_index;
        let mut empty_hashes_iter = self.empty_hashes.iter();
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();

            let mut current_hash = empty_hashes_iter.next().unwrap().clone();
            let mut sibling_hash = current_hash.clone();

            if self.tree.contains_key(&current_node) {
                match self.tree.get(&current_node) {
                    Some(x) => current_hash = x.clone(),
                    _ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
                }
            }

            if self.tree.contains_key(&sibling_node) {
                match self.tree.get(&sibling_node) {
                    Some(x) => sibling_hash = x.clone(),
                    _ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
                }
            }

            if is_left_child(current_node) {
                path.push((current_hash, sibling_hash));
            } else {
                path.push((sibling_hash, current_hash));
            }
            current_node = parent(current_node).unwrap();
        }

        if path.len() != (self.height - 1) as usize {
            Err(SparseMerkleTreeError::IncorrectPathLength(path.len()).into())
        } else {
            Ok(SparseMerkleTreePath {
                path,
                _marker: PhantomData,
            })
        }
    }

    /// generate a lookup proof
    pub fn generate_proof<L: ToBytes>(
        &self,
        index: u64,
        leaf: &L,
    ) -> Result<SparseMerkleTreePath<P>, Error> {
        let leaf_hash = P::LeafHash::evaluate(&self.leaf_param, &to_bytes!(leaf)?)?;
        let tree_height = self.height;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Check that the given index corresponds to the correct leaf.
        if let Some(x) = self.tree.get(&tree_index) {
            if &to_bytes!(leaf_hash)? != x {
                return Err(SparseMerkleTreeError::IncorrectTreeStructure.into());
            }
        }

        self.generate_membership_proof(index)
    }

    /*
    /// update the tree and provide a modifying proof
    pub fn update_and_prove<L: ToBytes>(
        &mut self,
        index: u64,
        new_leaf: &L,
    ) -> Result<SparseMerkleTreeTwoPaths<P>, Error> {
        let old_path = self.generate_membership_proof(index)?;

        let new_leaf_hash = P::LeafHash::evaluate(&self.leaf_param, to_bytes!(new_leaf)?)?;

        let tree_height = self.height;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Update the leaf and update the parents
        self.tree.insert(tree_index, to_bytes!(new_leaf_hash)?);

        // Iterate from the leaf up to the root, storing all intermediate hash values.
        let mut current_node = tree_index;
        current_node = parent(current_node).unwrap();

        let mut empty_hashes_iter = self.empty_hashes.iter();
        loop {
            let left_node = left_child(current_node);
            let right_node = right_child(current_node);

            let mut left_hash = empty_hashes_iter.next().unwrap().clone();
            let mut right_hash = left_hash.clone();

            if self.tree.contains_key(&left_node) {
                match self.tree.get(&left_node) {
                    Some(x) => left_hash = x.clone(),
                    _ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
                }
            }

            if self.tree.contains_key(&right_node) {
                match self.tree.get(&right_node) {
                    Some(x) => right_hash = x.clone(),
                    _ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
                }
            }

            let node_hash =
                P::TwoToOneHash::evaluate(&self.two_to_one_param, left_hash, right_hash)?;
            self.tree.insert(current_node, to_bytes!(node_hash));

            if is_root(current_node) {
                break;
            }

            current_node = parent(current_node).unwrap();
        }

        match self.tree.get(&0) {
            Some(x) => self.root = Some((*x).clone()),
            None => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
        }

        let new_path = self.generate_proof(index, new_leaf)?;

        Ok(SparseMerkleTreeTwoPaths { old_path, new_path })
    }
    */

    /// Check if the tree is structurally valid
    pub fn validate(&self) -> Result<bool, Error> {
        /* Finding the leaf nodes */
        let last_level_index: u64 = (1u64 << (self.height - 1)) - 1;
        let mut middle_nodes: BTreeSet<u64> = BTreeSet::new();

        for key in self.tree.keys() {
            if *key >= last_level_index && !is_root(*key) {
                middle_nodes.insert(parent(*key).unwrap());
            }
        }

        for level in 0..self.height {
            for current_index in &middle_nodes {
                let left_index = left_child(*current_index);
                let right_index = right_child(*current_index);

                let mut left_hash = to_bytes!(self.empty_hashes[level as usize])?;
                let mut right_hash = to_bytes!(self.empty_hashes[level as usize])?;

                if self.tree.contains_key(&left_index) {
                    match self.tree.get(&left_index) {
                        Some(x) => left_hash = to_bytes!(x)?,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                if self.tree.contains_key(&right_index) {
                    match self.tree.get(&right_index) {
                        Some(x) => right_hash = to_bytes!(x)?,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                let hash =
                    P::TwoToOneHash::evaluate(&self.two_to_one_param, &left_hash, &right_hash)?;

                match self.tree.get(current_index) {
                    Some(x) => {
                        if x != &to_bytes!(hash)? {
                            return Ok(false);
                        }
                    }
                    _ => {
                        return Ok(false);
                    }
                }
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        Ok(true)
    }
}

/// error for Merkle sparse tree
#[derive(Debug)]
pub enum SparseMerkleTreeError {
    /// the path's length does not work for this tree
    IncorrectPathLength(usize),
    /// tree structure is incorrect, some nodes are missing
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
fn convert_index_to_last_level(index: u64, tree_height: u64) -> u64 {
    index + (1 << (tree_height - 1)) - 1
}

/// Returns the byte representation of H(empty), H(H(empty), H(empty)), etc.
fn gen_empty_hashes<P: TreeConfig, L: ToBytes + Default>(
    leaf_param: &LeafParam<P>,
    two_to_one_param: &TwoToOneParam<P>,
    height: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut empty_hashes = Vec::with_capacity(height.try_into().unwrap());

    // Compute and store v := H(empty)
    let mut empty_hash_bytes = {
        let empty_leaf_bytes = to_bytes!(L::default())?;
        let empty_hash = P::LeafHash::evaluate(&leaf_param, &empty_leaf_bytes)?;
        to_bytes!(empty_hash)?
    };
    empty_hashes.push(empty_hash_bytes.clone());

    // Compute v := H(v, v) iteratively, storing intermediate results
    for _ in 1..=height {
        let empty_hash =
            P::TwoToOneHash::evaluate(two_to_one_param, &empty_hash_bytes, &empty_hash_bytes)?;
        empty_hash_bytes = to_bytes!(empty_hash)?;
        empty_hashes.push(empty_hash_bytes.clone());
    }

    Ok(empty_hashes)
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

    type Leaf = [u8; 8];

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63;
        const NUM_WINDOWS: usize = 17;
    }

    type H = bowe_hopwood::CRH<EdwardsParameters, Window>;

    #[derive(Clone)]
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }
    type JubJubMerkleTree = SparseMerkleTree<JubJubMerkleTreeParams>;

    const HEIGHT: u64 = 32;

    #[test]
    fn test_membership() {
        let mut rng = ark_std::test_rng();

        // Setup hashing params
        let leaf_param = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_param = <H as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Construct a tree of size 4
        let mut leaves: BTreeMap<u64, Leaf> = BTreeMap::new();
        for i in 0..4u8 {
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
            /*
            assert!(proof
                .verify_with_index(&crh_parameters, &root, &leaf, *i)
                .unwrap());
            */
        }

        // Now generate proofs and verify that they don't validate under an incorrect root
        let root = vec![0u8; root.len()];
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(!proof
                .verify(&leaf_param, &two_to_one_param, &root, &leaf)
                .unwrap());
            /*
            assert!(proof
                .verify_with_index(&crh_parameters, &root, &leaf, *i)
                .unwrap());
            */
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
                .verify_with_index(&crh_parameters, &root, &leaf, *i)
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
                .verify_with_index(&crh_parameters, &root, &leaf, *i)
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
                        .verify_with_index(&crh_parameters, &old_root, &old_leaf, *i)
                        .unwrap());
                    assert!(
                        !(old_leaf_membership_proof
                            .verify_with_index(&crh_parameters, &new_root, &old_leaf, *i)
                            .unwrap())
                    );
                    assert!(new_leaf_membership_proof
                        .verify_with_index(&crh_parameters, &new_root, &new_leaf, *i)
                        .unwrap());
                    assert!(
                        !(new_leaf_membership_proof
                            .verify_with_index(&crh_parameters, &new_root, &old_leaf, *i)
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
                        .verify_with_index(&crh_parameters, &new_root, &new_leaf, *i)
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
