// This file was copied and modified from
// https://github.com/arkworks-rs/ivls/blob/57325dc45db4f1b5d42bed4796cd9ba2cd1fbd3c/src/building_blocks/mt/merkle_sparse_tree/constraints.rs
// under dual MIT/APACHE license.

use crate::sparse_merkle::{SparseMerkleTreePath, TreeConfig, TwoToOneDigest};

use ark_crypto_primitives::crh::{CRHGadget, TwoToOneCRHGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::{AllocatedBool, Boolean},
    eq::EqGadget,
    select::CondSelectGadget,
    R1CSVar, ToBytesGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::borrow::Borrow;

/// Gadgets for one Merkle tree path
#[derive(Debug)]
pub struct SparseMerkleTreePathVar<P, LeafH, TwoToOneH, ConstraintF>
where
    P: TreeConfig,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: PrimeField,
{
    leaf_hashes: (LeafH::OutputVar, LeafH::OutputVar),
    inner_hashes: Vec<(TwoToOneH::OutputVar, TwoToOneH::OutputVar)>,
}

impl<P, LeafH, TwoToOneH, ConstraintF> SparseMerkleTreePathVar<P, LeafH, TwoToOneH, ConstraintF>
where
    P: TreeConfig,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: PrimeField,
{
    /// check a lookup proof (does not enforce index consistency)
    pub fn check_membership(
        &self,
        cs: ConstraintSystemRef<ConstraintF>,
        leaf_param: &LeafH::ParametersVar,
        two_to_one_param: &TwoToOneH::ParametersVar,
        root: &TwoToOneH::OutputVar,
        leaf: impl ToBytesGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership(
            cs,
            leaf_param,
            two_to_one_param,
            root,
            leaf,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a lookup proof (does not enforce index consistency)
    pub fn conditionally_check_membership(
        &self,
        cs: ConstraintSystemRef<ConstraintF>,
        leaf_param: &LeafH::ParametersVar,
        two_to_one_param: &TwoToOneH::ParametersVar,
        root: &TwoToOneH::OutputVar,
        leaf: impl ToBytesGadget<ConstraintF>,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        let claimed_leaf_hash = LeafH::evaluate(leaf_param, &leaf.to_bytes()?)?;

        // Check if leaf is one of the bottom-most siblings.
        let leaf_is_left =
            Boolean::Is(AllocatedBool::new_witness(ns!(cs, "leaf_is_left"), || {
                Ok(claimed_leaf_hash.value()? == self.leaf_hashes.0.value()?)
            })?);

        let leaf_hash = LeafH::OutputVar::conditionally_select(
            &leaf_is_left,
            &self.leaf_hashes.0,
            &self.leaf_hashes.1,
        )?;
        claimed_leaf_hash.conditional_enforce_equal(&leaf_hash, should_enforce)?;

        // Check levels between leaf level and root.
        let mut previous_hash = TwoToOneH::evaluate(
            two_to_one_param,
            &self.leaf_hashes.0.to_bytes()?,
            &self.leaf_hashes.1.to_bytes()?,
        )?;
        for (ref left_hash, ref right_hash) in &self.inner_hashes {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = Boolean::Is(AllocatedBool::new_witness(
                ark_relations::ns!(cs, "previous_is_left"),
                || Ok(previous_hash.value()? == left_hash.value()?),
            )?);

            previous_hash.conditional_enforce_equal(
                &TwoToOneH::OutputVar::conditionally_select(
                    &previous_is_left,
                    left_hash,
                    right_hash,
                )?,
                should_enforce,
            )?;

            previous_hash = TwoToOneH::evaluate(
                two_to_one_param,
                &left_hash.to_bytes()?,
                &right_hash.to_bytes()?,
            )?;
        }

        root.conditional_enforce_equal(&previous_hash, should_enforce)
    }

    fn new_variable<T: Borrow<SparseMerkleTreePath<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
        height: u32,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        // Compute the given closure to get a path
        let path_val = f().ok();
        let path: Option<&SparseMerkleTreePath<P>> = path_val.as_ref().map(|p| p.borrow());

        let left_leaf_hash = path.map(|p| &p.leaf_hashes.0);
        let right_leaf_hash = path.map(|p| &p.leaf_hashes.1);

        // Witness the leaves
        let leaf_hashes_var = (
            LeafH::OutputVar::new_variable(
                ns!(cs, "left_leaf"),
                || left_leaf_hash.ok_or(SynthesisError::AssignmentMissing),
                mode,
            )?,
            LeafH::OutputVar::new_variable(
                ns!(cs, "right_leaf"),
                || right_leaf_hash.ok_or(SynthesisError::AssignmentMissing),
                mode,
            )?,
        );

        // Now to populate the inner hashes
        let mut inner_hashes_var: Vec<(TwoToOneH::OutputVar, TwoToOneH::OutputVar)> = Vec::new();

        // If path is set, use its real contents
        if let Some(p) = path {
            for (ref left_hash, ref right_hash) in &p.inner_hashes {
                let left_hash_var =
                    TwoToOneH::OutputVar::new_variable(ns!(cs, "l_child"), || Ok(left_hash), mode)?;
                let right_hash_var = TwoToOneH::OutputVar::new_variable(
                    ns!(cs, "r_child"),
                    || Ok(right_hash),
                    mode,
                )?;

                inner_hashes_var.push((left_hash_var, right_hash_var));
            }
        } else {
            // If path is not set, then make the appropriate number (height-2) of placeholder vars
            let e: Result<&TwoToOneDigest<P>, _> = Err(SynthesisError::AssignmentMissing);

            for _ in 0..(height - 2) {
                let left = TwoToOneH::OutputVar::new_variable(ns!(cs, "l_child"), || e, mode)?;
                let right = TwoToOneH::OutputVar::new_variable(ns!(cs, "r_child"), || e, mode)?;
                inner_hashes_var.push((left, right));
            }
        }

        Ok(SparseMerkleTreePathVar {
            leaf_hashes: leaf_hashes_var,
            inner_hashes: inner_hashes_var,
        })
    }
    pub fn new_constant(
        cs: impl Into<Namespace<ConstraintF>>,
        t: impl Borrow<SparseMerkleTreePath<P>>,
        height: u32,
    ) -> Result<Self, SynthesisError> {
        Self::new_variable(cs, || Ok(t), AllocationMode::Constant, height)
    }
    pub fn new_input<T: Borrow<SparseMerkleTreePath<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        height: u32,
    ) -> Result<Self, SynthesisError> {
        Self::new_variable(cs, f, AllocationMode::Input, height)
    }

    pub fn new_witness<T: Borrow<SparseMerkleTreePath<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        height: u32,
    ) -> Result<Self, SynthesisError> {
        Self::new_variable(cs, f, AllocationMode::Witness, height)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sparse_merkle::SparseMerkleTree;

    use std::collections::BTreeMap;

    use ark_crypto_primitives::{
        crh::{bowe_hopwood, pedersen, TwoToOneCRH, CRH},
        merkle_tree::Config,
    };
    use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsParameters, Fq};
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
    use ark_relations::{ns, r1cs::ConstraintSystem};
    use ark_std::rand::{Rng, RngCore};

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63;
        const NUM_WINDOWS: usize = 9;
    }

    type H = bowe_hopwood::CRH<EdwardsParameters, Window>;
    type HG = bowe_hopwood::constraints::CRHGadget<EdwardsParameters, FqVar>;

    #[derive(Clone)]
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }

    type JubJubMerkleTree = SparseMerkleTree<JubJubMerkleTreeParams>;
    type Leaf = [u8; 8];
    const NUM_LEAVES: usize = 5;
    const HEIGHT: u32 = 32;

    // Make a tree and check the membership of all the leaves. When use_bad_root is set, the checks
    // should fail.
    fn generate_merkle_tree<R: Rng>(
        rng: &mut R,
        height: u32,
        leaves: &BTreeMap<u64, Leaf>,
        use_bad_root: bool,
    ) {
        // Setup hashing params
        let leaf_param = <H as CRH>::setup(rng).unwrap();
        let two_to_one_param = <H as TwoToOneCRH>::setup(rng).unwrap();

        // Construct a tree of size 4
        let tree =
            JubJubMerkleTree::new(leaf_param.clone(), two_to_one_param.clone(), height, leaves)
                .unwrap();

        let root: Fq = tree.root();
        let mut satisfied = true;
        for (i, leaf) in leaves.iter() {
            let cs_sys = ConstraintSystem::<Fq>::new();
            let cs = ConstraintSystemRef::new(cs_sys);
            let proof = tree.generate_proof(*i, &leaf).unwrap();

            // Baseline check that the proof is indeed correct
            assert!(proof
                .verify(&leaf_param, &two_to_one_param, &root, &leaf)
                .unwrap());

            // Allocate params
            let leaf_param_var = <HG as CRHGadget<H, _>>::ParametersVar::new_witness(
                ns!(cs, "parameters_var"),
                || Ok(&leaf_param),
            )
            .unwrap();
            let two_to_one_param_var = <HG as TwoToOneCRHGadget<H, _>>::ParametersVar::new_witness(
                ns!(cs, "parameters_var"),
                || Ok(&two_to_one_param),
            )
            .unwrap();

            // Allocate Merkle Tree Root
            let root_var =
                <<HG as TwoToOneCRHGadget<H, Fq>>::OutputVar as AllocVar<Fq, _>>::new_witness(
                    ns!(cs, "new_digest"),
                    || {
                        if use_bad_root {
                            Ok(<H as TwoToOneCRH>::Output::default())
                        } else {
                            Ok(root)
                        }
                    },
                )
                .unwrap();

            // Allocate leaf and index
            let leaf_bytes_var = UInt8::constant_vec(leaf);

            // Allocate Merkle Tree Path
            let cw = SparseMerkleTreePathVar::<_, HG, HG, _>::new_witness(
                ns!(cs, "new_witness"),
                || Ok(proof),
                height,
            )
            .unwrap();

            cw.check_membership(
                ns!(cs, "check_membership").cs(),
                &leaf_param_var,
                &two_to_one_param_var,
                &root_var,
                leaf_bytes_var.as_slice(),
            )
            .unwrap();

            if !cs.is_satisfied().unwrap() {
                satisfied = false;
                println!(
                    "Unsatisfied constraint: {}",
                    cs.which_is_unsatisfied().unwrap().unwrap()
                );
            }
        }

        assert!(satisfied);
    }

    #[test]
    fn good_root_membership_test() {
        let mut rng = ark_std::test_rng();

        // Generate random leaves
        let mut leaves: BTreeMap<u64, Leaf> = BTreeMap::new();
        for i in 0..NUM_LEAVES {
            let mut input = Leaf::default();
            rng.fill_bytes(&mut input);
            leaves.insert(i as u64, input);
        }

        // Make a merkle tree
        generate_merkle_tree(&mut rng, HEIGHT, &leaves, false);
    }

    #[should_panic]
    #[test]
    fn bad_root_membership_test() {
        let mut rng = ark_std::test_rng();

        // Generate random leaves
        let mut leaves: BTreeMap<u64, Leaf> = BTreeMap::new();
        for i in 0..NUM_LEAVES {
            let mut input = Leaf::default();
            rng.fill_bytes(&mut input);
            leaves.insert(i as u64, input);
        }

        // Make a merkle tree
        generate_merkle_tree(&mut rng, HEIGHT, &leaves, true);
    }
}
