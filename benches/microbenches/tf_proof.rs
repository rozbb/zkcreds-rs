///! Defines a single Groth16 proof for cred ∈ tree ∧ tree ∈ forest. This is a pared down version
///of monolithic_proof.rs
use zkcreds::{
    com_forest::{ComForestRoots, ForestMembershipProver},
    com_tree::{default_auth_path, ComTreePath, TreeMembershipProver},
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
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;
use groth16::{
    Proof as Groth16Proof, ProvingKey as Groth16ProvingKey, VerifyingKey as Groth16VerifyingKey,
};
use linkg16::groth16;

// Tree-forest prover. A single Groth16 proof for cred ∈ tree ∧ tree ∈ forest
struct TfProver<ConstraintF, AC, ACG, H, HG>
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
    for TfProver<ConstraintF, AC, ACG, H, HG>
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
        let attrs_com = &self.tree_prover.attrs_com;

        let attrs_com_var =
            ACG::OutputVar::new_witness(ns!(cs, "attrs com var"), || Ok(attrs_com.clone()))?;

        // Witness the public variables. In ALL zkcreds proofs, it's the commitment to the
        // attributes and the merkle root
        let root_var =
            HG::OutputVar::new_witness(ns!(cs, "root var"), || Ok(self.tree_prover.root.clone()))?;

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
pub fn gen_tf_crs<R, E, AC, ACG, H, HG>(
    rng: &mut R,
    crh_param: H::Parameters,
    height: u32,
    num_trees: usize,
) -> Result<Groth16ProvingKey<E>, SynthesisError>
where
    R: Rng,
    E: PairingEngine,
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

    let tf_prover = TfProver {
        tree_prover,
        forest_prover,
    };

    groth16::generate_random_parameters(tf_prover, rng)
}

pub fn prove_tf<R, E, AC, ACG, H, HG>(
    rng: &mut R,
    pk: &Groth16ProvingKey<E>,
    two_to_one_params: &H::Parameters,
    roots: &ComForestRoots<E::Fr, H>,
    auth_path: &ComTreePath<E::Fr, H, AC>,
    attrs_com: AC::Output,
) -> Result<Groth16Proof<E>, SynthesisError>
where
    R: Rng,
    E: PairingEngine,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let member_root = auth_path.root();

    // Construct the prover with all the relevant info, and prove
    let tree_prover: TreeMembershipProver<E::Fr, AC, ACG, H, HG> = TreeMembershipProver {
        height: auth_path.path.height(),
        crh_param: two_to_one_params.clone(),
        attrs_com: attrs_com.clone(),
        root: member_root.clone(),
        auth_path: Some(auth_path.path.clone()),
        _marker: PhantomData,
    };

    let forest_prover = ForestMembershipProver::<E::Fr, AC, ACG, H, HG> {
        roots: roots.roots.clone(),
        attrs_com,
        member_root,
        _marker: PhantomData,
    };

    let monolith_prover = TfProver {
        tree_prover,
        forest_prover,
    };

    groth16::create_random_proof(monolith_prover, pk, rng)
}

pub fn verify_tf<E, AC, ACG, H, HG>(
    vk: &Groth16VerifyingKey<E>,
    roots: &ComForestRoots<E::Fr, H>,
    proof: &Groth16Proof<E>,
) -> Result<bool, SynthesisError>
where
    E: PairingEngine,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    groth16::verify_proof(vk, proof, &roots.public_inputs())
}
