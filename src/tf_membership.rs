//! We define a gadget that proofs tree and forest membership simulatneously
use crate::{
    attrs::Attrs,
    com_forest::ForestMembershipProver,
    com_tree::{default_auth_path, TreeMembershipProver},
    identity_crh::{IdentityCRHGadget, UnitVar},
    sparse_merkle::constraints::SparseMerkleTreePathVar,
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{constraints::TwoToOneCRHGadget, TwoToOneCRH},
};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::{Proof as Groth16Proof, ProvingKey as Groth16ProvingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;

// Tree & Forest membership. Proves cred ∈ tree and tree ∈ forest
struct TfMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    tree_prover: TreeMembershipProver<ConstraintF, AC, ACG, H, HG>,
    forest_prover: ForestMembershipProver<ConstraintF, AC, ACG, H, HG>,
}

impl<ConstraintF, AC, ACG, H, HG> ConstraintSynthesizer<ConstraintF>
    for TfMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let tree_height = self.tree_prover.height;

        // Witness the public variables. In ALL zeronym proofs, it's the commitment to the
        // attributes and the merkle root
        let attrs_com_var = ACG::OutputVar::new_input(ns!(cs, "attrs com var"), || {
            Ok(self.tree_prover.attrs_com.clone())
        })?;
        let root_var =
            HG::OutputVar::new_input(ns!(cs, "root var"), || Ok(self.tree_prover.root.clone()))?;

        // Now we do the tree membership proof. Input the two-to-one params
        let crh_param_var = HG::ParametersVar::new_constant(
            ns!(cs, "two_to_one param"),
            &self.tree_prover.crh_param,
        )?;
        // This is a placeholder value. We don't actually use leaf hashes
        let leaf_param_var = UnitVar::default();

        // Witness the roots
        let all_roots = Vec::<HG::OutputVar>::new_input(ns!(cs, "roots"), || {
            Ok(self.forest_prover.roots.clone())
        })?;

        // Witness the auth auth
        let auth_path = self
            .tree_prover
            .auth_path
            .clone()
            .unwrap_or_else(|| default_auth_path::<AC, H>(tree_height));
        let path_var = SparseMerkleTreePathVar::<_, IdentityCRHGadget, HG, _>::new_witness(
            ns!(cs, "auth path"),
            || Ok(auth_path),
            tree_height,
        )?;

        self.forest_prover.circuit(&root_var, &all_roots)?;
        self.tree_prover.circuit(
            &attrs_com_var,
            &root_var,
            &path_var,
            &crh_param_var,
            &leaf_param_var,
        )
    }
}

/// Generates the membership proving key for this tree
pub fn gen_memb_crs<R, E, A, AC, ACG, H, HG>(
    rng: &mut R,
    crh_param: H::Parameters,
    height: u32,
    num_trees: usize,
) -> Result<Groth16ProvingKey<E>, SynthesisError>
where
    R: Rng,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    // Make a placeholder tree
    let tree_prover: TreeMembershipProver<E::Fr, AC, ACG, H, HG> = TreeMembershipProver {
        height,
        crh_param,
        attrs_com: Default::default(),
        root: Default::default(),
        //root: self.tree.root(),
        //root_com_nonce: self.nonce,
        auth_path: None,
        _marker: PhantomData,
    };

    // Make a placeholder forest
    let roots = vec![H::Output::default(); num_trees];
    let attrs_com = AC::Output::default();
    let member_root = H::Output::default();
    let forest_prover = ForestMembershipProver::<E::Fr, AC, ACG, H, HG> {
        roots,
        attrs_com,
        member_root,
        _marker: PhantomData,
    };

    let tf_prover = TfMembershipProver {
        tree_prover,
        forest_prover,
    };

    ark_groth16::generate_random_parameters(tf_prover, rng)
}
