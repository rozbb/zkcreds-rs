use crate::{
    common::Credential,
    proof_of_issuance::ProofOfIssuanceCircuit,
    sparse_merkle::{SparseMerkleTree, SparseMerkleTreePath, TwoToOneDigest},
    Error,
};

use std::collections::BTreeMap;

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::{
    crh::{bowe_hopwood, pedersen, TwoToOneCRH, CRH},
    merkle_tree::{Config as TreeConfig, LeafParam, TwoToOneParam},
};
use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsParameters};
use ark_ff::{to_bytes, ToBytes, ToConstraintField};
use ark_groth16::{
    generator::generate_random_parameters,
    prover::create_random_proof,
    verifier::{prepare_verifying_key, verify_proof},
    PreparedVerifyingKey, Proof, ProvingKey,
};
use ark_std::{
    io::{Result as IoResult, Write},
    rand::{prelude::StdRng, SeedableRng},
};
use lazy_static::lazy_static;

lazy_static! {
    static ref LEAF_PARAM: LeafParam<P> = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write(b"zeronym-leaf-hash-param").unwrap();
            R::from_seed(seed)
        };
        <<P as TreeConfig>::LeafHash as CRH>::setup(&mut rng).unwrap()
    };
    static ref TWO_TO_ONE_PARAM: TwoToOneParam<P> = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write(b"zeronym-two-to-one-hash-param").unwrap();
            R::from_seed(seed)
        };
        <<P as TreeConfig>::TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}

// Size params for the merkle two-to-one CRH. NUM_WINDOWS should be as small as possible. You'll
// know when it's too small because anything using the sparse merkle tree will panic.
#[derive(Clone)]
pub struct TwoToOneWindow;
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 9;
}

// Size params for the merkle leaf-level CRH. NUM_WINDOWS should be as small as possible. You'll
// know when it's too small because anything using the sparse merkle tree will panic.
#[derive(Clone)]
pub struct LeafWindow;
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 2;
}

// Size params for the whole merkle tree
struct JubJubMerkleTreeParams;
impl TreeConfig for JubJubMerkleTreeParams {
    type LeafHash = LeafH;
    type TwoToOneHash = TwoToOneH;
}

// Type aliases for convenience
type LeafH = bowe_hopwood::CRH<EdwardsParameters, LeafWindow>;
type TwoToOneH = bowe_hopwood::CRH<EdwardsParameters, TwoToOneWindow>;
type HG = bowe_hopwood::constraints::CRHGadget<EdwardsParameters, FqVar>;
type E = Bls12_381;
type P = JubJubMerkleTreeParams;
type R = StdRng;

/// Get a secure random number generator
pub fn get_rng() -> R {
    R::from_entropy()
}

/// The proving key for zero-knowledge membership proofs
pub struct ZkProvingKey {
    groth_pk: ProvingKey<E>,
    tree_height: u32,
}
/// The verifying key for zero-knowledge membership proofs
pub type ZkVerifyingKey = PreparedVerifyingKey<E>;
/// A zero-knowledge membership proof
pub type ZkProof = Proof<E>;

/// Sets up the proving and verifying keys for the membership proofs. `tree_height` is the height
/// of the [`IssuanceList`] tree that will be used. That is, `2^tree_height` is the number of
/// commitments that can be stored in a single [`IssuanceList`].
pub fn zk_proof_setup(rng: &mut R, tree_height: u32) -> (ZkProvingKey, ZkVerifyingKey) {
    let param_gen_circuit = ProofOfIssuanceCircuit::<P, Fr, HG, HG>::new_placeholder(
        tree_height,
        LEAF_PARAM.clone(),
        TWO_TO_ONE_PARAM.clone(),
    );
    let groth_pk = generate_random_parameters::<E, _, _>(param_gen_circuit, rng).unwrap();
    let groth_pvk = prepare_verifying_key(&groth_pk.vk);

    let pk = ZkProvingKey {
        groth_pk,
        tree_height,
    };

    (pk, groth_pvk)
}

// Wrapper structs for the sake of a simple API
/// A commitment to a `Cred`
#[derive(Default)]
pub struct Com(TwoToOneDigest<P>);
/// A secret credential
pub struct Cred(Credential);
/// The opening to a credential commitment
pub struct ComNonce(Credential);

impl ToBytes for Com {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}

impl Cred {
    /// Make a new random credential
    pub fn gen(rng: &mut R) -> Self {
        Cred(Credential::gen(rng))
    }

    /// Commit to this credential, getting a commitment and an opening nonce
    pub fn commit(&self, rng: &mut R) -> Result<(Com, ComNonce), Error> {
        let nonce = Credential::gen(rng);
        let com = <<P as TreeConfig>::TwoToOneHash as TwoToOneCRH>::evaluate(
            &*TWO_TO_ONE_PARAM,
            &to_bytes!(self.0)?,
            &to_bytes!(nonce)?,
        )?;

        Ok((Com(com), ComNonce(nonce)))
    }
}

/// A merkle tree of all the credential commitments that are issued
pub struct IssuanceList(SparseMerkleTree<P>);
/// A proof of membership in an [`IssuanceList`]. To make this a zero-knowledge proof, call
/// [`AuthPath::zk_prove`].
pub struct AuthPath(SparseMerkleTreePath<P>);
/// The root node of the issuance merkle tree. This is all the input that's needed to verify a
/// proof of membership.
pub struct IssuanceListRoot(TwoToOneDigest<P>);

impl IssuanceList {
    /// Makes an empty list with capacity `2^log_capacity`
    pub fn empty(log_capacity: u32) -> IssuanceList {
        IssuanceList(SparseMerkleTree::empty::<Com>(
            LEAF_PARAM.clone(),
            TWO_TO_ONE_PARAM.clone(),
            log_capacity,
        ))
    }

    /// Makes a list of capacity `2^log_capacity` that's populated with all the given commitments
    /// at the given indices
    ///
    /// Panics
    /// =====
    /// Panics if any key in `coms` is greater than or equal to `2^log_capacity`
    pub fn new(log_capacity: u32, coms: &BTreeMap<u64, Com>) -> IssuanceList {
        let tree = SparseMerkleTree::new::<Com>(
            LEAF_PARAM.clone(),
            TWO_TO_ONE_PARAM.clone(),
            log_capacity,
            coms,
        )
        .expect("could not instantiate SparseMerkleTree");

        IssuanceList(tree)
    }

    /// Inserts a commitment at index `idx`. This will overwrite the existing entry if there is one.
    ///
    /// Panics
    /// =====
    /// Panics when `idx >= 2^log_capacity`
    pub fn insert(&mut self, idx: u64, com: &Com) {
        self.0.insert(idx, com).expect("could not insert item");
    }

    /// Removes the entry at index `idx`, if one exists
    ///
    /// Panics
    /// =====
    /// Panics when `idx >= 2^log_capacity`
    pub fn remove(&mut self, idx: u64) {
        self.0.remove(idx).expect("could not remove item");
    }

    /// Computes a proof of membership of the `com` at index `idx`. Errors when `com` is not
    /// actually at `idx`.
    ///
    /// Panics
    /// =====
    /// Panics when `idx >= 2^log_capacity`
    pub fn get_auth_path(&self, idx: u64, com: &Com) -> Result<AuthPath, Error> {
        self.0.generate_proof(idx, com).map(AuthPath)
    }

    /// Returns the root node of this list. This is used for verification.
    pub fn root(&self) -> IssuanceListRoot {
        IssuanceListRoot(self.0.root())
    }
}

/// Verifies a zero-knowledge proof of membership
#[must_use]
pub fn zk_verify(vk: &ZkVerifyingKey, root: &IssuanceListRoot, proof: &ZkProof) -> bool {
    let root_input = root.0.to_field_elements().unwrap();
    verify_proof(vk, proof, &root_input).expect("circuit verification failed")
}

impl AuthPath {
    /// Constructs a zero-knowledge proof that this `AuthPath` is valid
    pub fn zk_prove(
        &self,
        rng: &mut R,
        pk: &ZkProvingKey,
        opening: (Cred, ComNonce),
    ) -> Result<ZkProof, Error> {
        let (cred, nonce) = opening;
        let root_hash = self.0.root(&*TWO_TO_ONE_PARAM)?;

        let circuit = ProofOfIssuanceCircuit::<P, Fr, HG, HG>::new(
            pk.tree_height,
            LEAF_PARAM.clone(),
            TWO_TO_ONE_PARAM.clone(),
            root_hash,
            (cred.0, nonce.0),
            self.0.clone(),
        );

        let proof = create_random_proof::<E, _, _>(circuit, &pk.groth_pk, rng)?;
        Ok(proof)
    }
}

#[test]
fn test_api_correctness() {
    // Set up the RNG and CRS
    let mut rng = get_rng();
    let tree_height: u32 = 32;
    let (pk, vk) = zk_proof_setup(&mut rng, tree_height);

    // Client: Make a credential and commit to it. Send commitment to the list holder
    let cred = Cred::gen(&mut rng);
    let (com, com_nonce) = cred.commit(&mut rng).expect("couldn't commit to cred");

    // Make a list and insert the commitment in a free space. Share the list with the world.
    let first_free_idx = 0u64;
    let mut global_list = IssuanceList::empty(tree_height);
    global_list.insert(first_free_idx, &com);

    // Client: Get the auth path in the list and use it to make a ZK proof
    let auth_path = global_list
        .get_auth_path(first_free_idx, &com)
        .expect("couldn't get auth path");
    let opening = (cred, com_nonce);
    let membership_proof = auth_path
        .zk_prove(&mut rng, &pk, opening)
        .expect("couldn't prove membership");

    // Observer: Verify proof wrt the issuance list
    let list_root = global_list.root();
    assert!(zk_verify(&vk, &list_root, &membership_proof));
}
