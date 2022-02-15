use crate::{
    common::AttrString,
    proof_of_issuance::TreeMembershipProver,
    sparse_merkle::{SparseMerkleTree, SparseMerkleTreePath, TwoToOneDigest},
    Error,
};

use std::collections::BTreeMap;

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::{
    commitment::{self, pedersen::Parameters as CommitmentParameters, CommitmentScheme},
    crh::{bowe_hopwood, pedersen, TwoToOneCRH, CRH},
    merkle_tree::{Config as TreeConfig, LeafParam, TwoToOneParam},
};
use ark_ed_on_bls12_381::{
    constraints::{EdwardsVar as JubjubVar, FqVar},
    EdwardsParameters, EdwardsProjective as Jubjub,
};
use ark_ff::{ToBytes, ToConstraintField, UniformRand};
use ark_groth16::{
    generator::generate_random_parameters,
    prover::{create_random_proof, rerandomize_proof},
    verifier::{prepare_verifying_key, verify_proof},
    Proof, ProvingKey, VerifyingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Result as IoResult, Write},
    rand::{prelude::StdRng, CryptoRng, Rng, SeedableRng},
};
use lazy_static::lazy_static;

// Initialize the hashing parameters deterministically
lazy_static! {
    static ref LEAF_PARAM: LeafParam<P> = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-leaf-hash-param").unwrap();
            StdRng::from_seed(seed)
        };
        <<P as TreeConfig>::LeafHash as CRH>::setup(&mut rng).unwrap()
    };
    static ref COM_PARAM: CommitmentParameters<Jubjub> = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        commitment::pedersen::Commitment::<Jubjub, CommitmentWindow>::setup(&mut rng).unwrap()
    };
    static ref TWO_TO_ONE_PARAM: TwoToOneParam<P> = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zeronym-two-to-one-hash-param").unwrap();
            StdRng::from_seed(seed)
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
    const NUM_WINDOWS: usize = 3;
}

/// The Pedersen parameters for the attribute set commitment scheme
#[derive(Clone)]
pub struct CommitmentWindow;
impl pedersen::Window for CommitmentWindow {
    const WINDOW_SIZE: usize = 63;
    // This can be smaller than 8, but the program panics if it's not divisible by 8. Tracking
    // issue here: https://github.com/arkworks-rs/crypto-primitives/issues/76
    const NUM_WINDOWS: usize = 8;
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
/// A commitment to an `AttrString`
#[derive(CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct Com(<ComScheme as CommitmentScheme>::Output);
/// The opening to an attribute string commitment
pub struct ComNonce(<ComScheme as CommitmentScheme>::Randomness);

// This is so that IssuanceList is serializable
impl CanonicalSerialize for SparseMerkleTree<P> {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        // Just serialize everything except the hash params. Those are static
        self.height.serialize(&mut writer)?;
        self.leaf_hashes.serialize(&mut writer)?;
        self.inner_hashes.serialize(&mut writer)?;
        self.empty_hashes.serialize(&mut writer)?;

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.height.serialized_size()
            + self.leaf_hashes.serialized_size()
            + self.inner_hashes.serialized_size()
            + self.empty_hashes.serialized_size()
    }
}

// This is so that IssuanceList is deserializable
impl CanonicalDeserialize for SparseMerkleTree<P> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        use crate::sparse_merkle::{EmptyHashes, LeafDigest};

        // The params were never serialized. Recover them using the static values
        let leaf_param = LEAF_PARAM.clone();
        let two_to_one_param = TWO_TO_ONE_PARAM.clone();

        // Now deserialize everything else
        let height = u32::deserialize(&mut reader)?;
        let leaf_hashes = BTreeMap::<u64, LeafDigest<P>>::deserialize(&mut reader)?;
        let inner_hashes = BTreeMap::<u64, TwoToOneDigest<P>>::deserialize(&mut reader)?;
        let empty_hashes = EmptyHashes::<P>::deserialize(&mut reader)?;

        Ok(SparseMerkleTree {
            leaf_param,
            two_to_one_param,
            height,
            leaf_hashes,
            inner_hashes,
            empty_hashes,
        })
    }
}

/// The proving key for zero-knowledge membership proofs
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkProvingKey {
    groth_pk: ProvingKey<E>,
    log_capacity: u32,
}
/// The verifying key for zero-knowledge membership proofs
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkVerifyingKey(VerifyingKey<E>);
/// A zero-knowledge membership proof
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkProof(Proof<E>);

impl ZkProof {
    /// Rerandomizes the `ZkProof` so it looks like a fresh proof
    pub fn rerandomize<R>(&mut self, rng: &mut R, pk: &ZkProvingKey)
    where
        R: Rng + CryptoRng,
    {
        let new_proof = rerandomize_proof(rng, &pk.groth_pk.vk, &self.0);
        self.0 = new_proof;
    }
}

/// Sets up the proving and verifying keys for the membership proofs. `log_capacity` is the height
/// of the [`IssuanceList`] tree that will be used. That is, `2^log_capacity` is the number of
/// commitments that can be stored in a single [`IssuanceList`].
pub fn setup_zk_proof<R>(rng: &mut R, log_capacity: u32) -> (ZkProvingKey, ZkVerifyingKey)
where
    R: Rng + CryptoRng,
{
    let param_gen_circuit =
        TreeMembershipProver::<ComScheme, ComGadget, P, Fr, HG, HG>::new_placeholder(
            log_capacity,
            LEAF_PARAM.clone(),
            TWO_TO_ONE_PARAM.clone(),
            COM_PARAM.clone(),
        );
    let groth_pk = generate_random_parameters::<E, _, _>(param_gen_circuit, rng).unwrap();
    let vk = ZkVerifyingKey(groth_pk.vk.clone());
    let pk = ZkProvingKey {
        groth_pk,
        log_capacity,
    };

    (pk, vk)
}

// Wrapper structs for the sake of a simple API
type ComScheme = commitment::pedersen::Commitment<Jubjub, CommitmentWindow>;
type ComGadget = commitment::pedersen::constraints::CommGadget<Jubjub, JubjubVar, CommitmentWindow>;

impl AttrString {
    /// Commit to this credential, getting a commitment and an opening nonce
    pub fn commit<R>(&self, rng: &mut R) -> Result<(Com, ComNonce), Error>
    where
        R: Rng + CryptoRng,
    {
        let nonce = <ComScheme as CommitmentScheme>::Randomness::rand(rng);
        let com = <ComScheme as CommitmentScheme>::commit(&COM_PARAM, &self.0, &nonce)?;

        Ok((Com(com), ComNonce(nonce)))
    }
}

impl ToBytes for Com {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}
impl ToBytes for ComNonce {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}

/// A merkle tree of all the credential commitments that are issued
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuanceList(SparseMerkleTree<P>);
/// A proof of membership in an [`IssuanceList`]. To make this a zero-knowledge proof, call
/// [`AuthPath::zk_prove`].
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct AuthPath(SparseMerkleTreePath<P>);
/// The root node of the issuance merkle tree. This is all the input that's needed to verify a
/// proof of membership.
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
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

impl AuthPath {
    /// Constructs a zero-knowledge proof that this `AuthPath` is valid
    pub fn zk_prove<R>(
        &self,
        rng: &mut R,
        pk: &ZkProvingKey,
        opening: (AttrString, ComNonce),
    ) -> Result<ZkProof, Error>
    where
        R: Rng + CryptoRng,
    {
        let (attrs, nonce) = opening;
        let root_hash = self.0.root(&*TWO_TO_ONE_PARAM)?;

        let circuit = TreeMembershipProver::<ComScheme, ComGadget, P, Fr, HG, HG>::new(
            pk.log_capacity,
            LEAF_PARAM.clone(),
            TWO_TO_ONE_PARAM.clone(),
            COM_PARAM.clone(),
            root_hash,
            (attrs, nonce.0),
            self.0.clone(),
        );

        let proof = create_random_proof::<E, _, _>(circuit, &pk.groth_pk, rng)?;
        Ok(ZkProof(proof))
    }
}

// TODO: Small optimization: if PreparedVerifyingKey implemented CanonicalSerialize, we'd be able
// to use that instead of preparing on every verification. Currently it does not, because
// PairingEngine::G2Prepared does not impl CanonicalSerialize.
/// Verifies a zero-knowledge proof of membership
#[must_use]
pub fn zk_verify(vk: &ZkVerifyingKey, root: &IssuanceListRoot, proof: &ZkProof) -> bool {
    // Serialize the tree root
    let root_input = root.0.to_field_elements().unwrap();

    // Prepare the verifying key and verify
    let pvk = prepare_verifying_key(&vk.0);
    verify_proof(&pvk, &proof.0, &root_input).expect("circuit verification failed")
}

#[test]
fn test_api_correctness() {
    // Set up the RNG and CRS
    let mut rng = StdRng::from_entropy();
    let log_capacity: u32 = 32;
    let (pk, vk) = setup_zk_proof(&mut rng, log_capacity);

    // Client: Make some attributes and commit to it. Send commitment to the list holder
    let attrs = AttrString::gen(&mut rng);
    let (com, com_nonce) = attrs.commit(&mut rng).expect("couldn't commit to cred");

    // Make a list and insert the commitment in a free space. Share the list with the world.
    let first_free_idx = 0u64;
    let mut global_list = IssuanceList::empty(log_capacity);
    global_list.insert(first_free_idx, &com);
    let inserted_cred_idx = first_free_idx;

    // Client: Get the auth path in the list and use it to make a ZK proof
    let auth_path = global_list
        .get_auth_path(first_free_idx, &com)
        .expect("couldn't get auth path");

    let opening = (attrs, com_nonce);
    let start = std::time::Instant::now();
    let mut membership_proof = auth_path
        .zk_prove(&mut rng, &pk, opening)
        .expect("couldn't prove membership");
    println!("Proof time {:?}", start.elapsed());

    // Observer: Verify proof wrt the issuance list
    let list_root = global_list.root();
    assert!(zk_verify(&vk, &list_root, &membership_proof));

    // Rerandomize the proof and verify again
    membership_proof.rerandomize(&mut rng, &pk);
    assert!(zk_verify(&vk, &list_root, &membership_proof));

    // Now remove the credential from the list and ensure that the proof no longer works
    global_list.remove(inserted_cred_idx);
    let list_root = global_list.root();
    assert!(!zk_verify(&vk, &list_root, &membership_proof));
}
