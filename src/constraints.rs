use crate::merkle_forest::{MerkleForest, Path};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHGadget, TwoToOneCRHGadget},
    merkle_tree::{constraints::PathVar, Config},
};
use ark_ff::Field;
use ark_r1cs_std::{alloc::AllocVar, bits::uint8::UInt8, boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

pub struct MerkleProofCircuit<'a, ConstraintF, LeafH, P, TwoToOneH>
where
    ConstraintF: Field,
    P: Config,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    TwoToOneH::OutputVar: EqGadget<ConstraintF>,
{
    // Public inputs
    forest: &'a MerkleForest<P>,
    // Private inputs
    auth_path: Option<&'a Path<P>>,
    leaf_val: Vec<Option<u8>>,
    // Marker
    _marker: PhantomData<(ConstraintF, LeafH, TwoToOneH)>,
}

impl<'a, ConstraintF, LeafH, P, TwoToOneH> Clone
    for MerkleProofCircuit<'a, ConstraintF, LeafH, P, TwoToOneH>
where
    ConstraintF: Field,
    P: Config + Clone,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    TwoToOneH::OutputVar: EqGadget<ConstraintF>,
{
    fn clone(&self) -> MerkleProofCircuit<'a, ConstraintF, LeafH, P, TwoToOneH> {
        MerkleProofCircuit {
            forest: &self.forest,
            auth_path: self.auth_path.clone(),
            leaf_val: self.leaf_val.clone(),
            _marker: PhantomData,
        }
    }
}

impl<'a, ConstraintF, LeafH, P, TwoToOneH> MerkleProofCircuit<'a, ConstraintF, LeafH, P, TwoToOneH>
where
    ConstraintF: Field,
    P: Config,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    TwoToOneH::OutputVar: EqGadget<ConstraintF>,
{
    pub fn new_placeholder(
        forest: &MerkleForest<P>,
        num_leaf_bytes: usize,
    ) -> MerkleProofCircuit<ConstraintF, LeafH, P, TwoToOneH> {
        MerkleProofCircuit {
            forest,
            auth_path: None,
            leaf_val: vec![None; num_leaf_bytes],
            _marker: PhantomData,
        }
    }

    pub fn new(
        forest: &'a MerkleForest<P>,
        auth_path: &'a Path<P>,
        leaf_val_slice: &[u8],
    ) -> MerkleProofCircuit<'a, ConstraintF, LeafH, P, TwoToOneH> {
        let leaf_val: Vec<Option<u8>> = leaf_val_slice.iter().map(|b| Some(*b)).collect();

        MerkleProofCircuit {
            forest,
            auth_path: Some(auth_path),
            leaf_val,
            _marker: PhantomData,
        }
    }
}

impl<'a, ConstraintF, LeafH, P, TwoToOneH> ConstraintSynthesizer<ConstraintF>
    for MerkleProofCircuit<'a, ConstraintF, LeafH, P, TwoToOneH>
where
    ConstraintF: Field,
    P: Config,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    TwoToOneH::OutputVar: EqGadget<ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Get param vars
        let leaf_crh_param_var = LeafH::ParametersVar::new_constant(
            ark_relations::ns!(cs, "leaf_crh_parameter"),
            &self.forest.leaf_crh_param,
        )?;
        let two_to_one_crh_param_var = TwoToOneH::ParametersVar::new_constant(
            ark_relations::ns!(cs, "two_to_one_crh_parameter"),
            &self.forest.two_to_one_crh_param,
        )?;

        // Witness the leaf and path values
        let leaf_var = UInt8::new_witness_vec(ns!(cs, "leaf wit"), &self.leaf_val)?;
        let path_var: PathVar<_, LeafH, TwoToOneH, ConstraintF> =
            PathVar::new_witness(ns!(cs, "path wit"), || {
                self.auth_path.ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Compute the path root in zero knowledge
        let path_root_var = path_var.calculate_root(
            &leaf_crh_param_var,
            &two_to_one_crh_param_var,
            &leaf_var.as_slice(),
        )?;

        // Collect all the Merkle roots into vars
        let forest_root_vars: Result<
            Vec<<TwoToOneH as TwoToOneCRHGadget<_, _>>::OutputVar>,
            SynthesisError,
        > = self
            .forest
            .roots()
            .into_iter()
            .map(|root| {
                <TwoToOneH as TwoToOneCRHGadget<_, _>>::OutputVar::new_input(
                    ns!(cs, "root wit"),
                    || Ok(root),
                )
            })
            .collect();

        // Check whether the path root is equal to any one of the Merkle roots
        let mut proof_is_valid = Boolean::<ConstraintF>::constant(false);
        for candidate_root in forest_root_vars? {
            proof_is_valid = proof_is_valid.or(&candidate_root.is_eq(&path_root_var)?)?;
        }

        // Assert that the path root is equal to at least one of the Merkle roots
        proof_is_valid.enforce_equal(&Boolean::constant(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{merkle_forest::idx_1d_to_2d, test_util::Window4x256};

    use ark_crypto_primitives::crh::{pedersen, *};
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::Rng;

    type Leaf = [u8; 8];

    type H = pedersen::CRH<JubJub, Window4x256>;
    type HG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;

    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }
    type JubJubMerkleForest = MerkleForest<JubJubMerkleTreeParams>;

    #[test]
    fn constraint_test() {
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

        // Pick the leaf at index 106 to make a proof of
        let (leaf, auth_path) = {
            let i = 106;
            let (tree_idx, leaf_idx) = idx_1d_to_2d(i, num_trees, num_leaves);
            let tree = &forest.trees[tree_idx];
            let leaf = &leaves[i];
            let auth_path = tree.generate_proof(leaf_idx).unwrap();

            (leaf, auth_path)
        };

        // Construct the circuit which will prove the membership of leaf i
        let circuit = MerkleProofCircuit::<Fq, HG, JubJubMerkleTreeParams, HG>::new(
            &forest, &auth_path, leaf,
        );

        // Run the circuit and check that the constraints are satisfied
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "{} trees of {} leaves has {} constraints",
            num_trees,
            num_leaves / num_trees,
            cs.num_constraints()
        );
    }
}
