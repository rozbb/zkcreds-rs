use crate::{
    common::Credential,
    membership_circuit::MerkleMembershipCircuit,
    sparse_merkle::{SparseMerkleTree, SparseMerkleTreePath, TwoToOneDigest},
    Error,
};

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

#[derive(Clone)]
pub struct TwoToOneWindow;
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 9;
}

#[derive(Clone)]
pub struct LeafWindow;
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 4;
}

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

pub fn get_rng() -> R {
    R::from_entropy()
}

pub struct ZkProvingKey {
    groth_pk: ProvingKey<E>,
    tree_height: u32,
}
pub type ZkVerifyingKey = PreparedVerifyingKey<E>;
pub type ZkProof = Proof<E>;

fn get_hash_params<P>() -> (LeafParam<P>, TwoToOneParam<P>)
where
    P: TreeConfig,
{
    let mut rng = {
        let mut seed = [0u8; 32];
        let mut writer = &mut seed[..];
        writer.write(b"zeronym-hash-params").unwrap();
        R::from_seed(seed)
    };
    let leaf_param = <P::LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_param = <P::TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    (leaf_param, two_to_one_param)
}

pub fn zk_proof_setup(rng: &mut R, tree_height: u32) -> (ZkProvingKey, ZkVerifyingKey) {
    let (leaf_param, two_to_one_param) = get_hash_params::<P>();
    let param_gen_circuit = MerkleMembershipCircuit::<P, Fr, HG, HG>::new_placeholder(
        tree_height,
        leaf_param.clone(),
        two_to_one_param.clone(),
    );
    let groth_pk = generate_random_parameters::<E, _, _>(param_gen_circuit, rng).unwrap();
    let groth_pvk = prepare_verifying_key(&groth_pk.vk);

    let pk = ZkProvingKey {
        groth_pk,
        tree_height,
    };

    (pk, groth_pvk)
}

#[derive(Default)]
pub struct Com(TwoToOneDigest<P>);
pub struct Cred(Credential);
pub struct ComNonce(Credential);

impl ToBytes for Com {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}

impl Cred {
    pub fn gen(rng: &mut R) -> Self {
        Cred(Credential::gen(rng))
    }

    /// Commit to this credential, getting a commitment and an opening nonce
    pub fn commit(&self, rng: &mut R) -> Result<(Com, ComNonce), Error> {
        let (_, two_to_one_param) = get_hash_params::<P>();

        let nonce = Credential::gen(rng);
        let com = <<P as TreeConfig>::TwoToOneHash as TwoToOneCRH>::evaluate(
            &two_to_one_param,
            &to_bytes!(self.0)?,
            &to_bytes!(nonce)?,
        )?;

        Ok((Com(com), ComNonce(nonce)))
    }
}

pub struct IssuanceList(SparseMerkleTree<P>);
pub struct AuthPath(SparseMerkleTreePath<P>);
pub struct IssuanceListRoot(TwoToOneDigest<P>);

impl IssuanceList {
    pub fn new(tree_height: u32) -> IssuanceList {
        let (leaf_param, two_to_one_param) = get_hash_params::<P>();
        IssuanceList(SparseMerkleTree::blank::<Com>(
            leaf_param,
            two_to_one_param,
            tree_height,
        ))
    }

    pub fn insert(&mut self, idx: u64, com: &Com) -> Result<(), Error> {
        self.0.insert(idx, com)
    }

    pub fn get_auth_path(&self, idx: u64, com: &Com) -> Result<AuthPath, Error> {
        let path = self.0.generate_proof(idx, com).unwrap();
        Ok(AuthPath(path))
    }

    pub fn root(&self) -> IssuanceListRoot {
        IssuanceListRoot(self.0.root())
    }
}

pub fn zk_verify(
    vk: &ZkVerifyingKey,
    root: &IssuanceListRoot,
    proof: &ZkProof,
) -> Result<bool, Error> {
    let root_input = root.0.to_field_elements().unwrap();
    let valid = verify_proof(vk, proof, &root_input)?;

    Ok(valid)
}

impl AuthPath {
    pub fn zk_prove(
        &self,
        rng: &mut R,
        pk: &ZkProvingKey,
        opening: (Cred, ComNonce),
    ) -> Result<ZkProof, Error> {
        let (leaf_param, two_to_one_param) = get_hash_params::<P>();
        let (cred, nonce) = opening;
        let root_hash = self.0.root(&two_to_one_param)?;

        let circuit = MerkleMembershipCircuit::<P, Fr, HG, HG>::new(
            pk.tree_height,
            leaf_param,
            two_to_one_param,
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
    let mut global_list = IssuanceList::new(tree_height);
    global_list
        .insert(first_free_idx, &com)
        .expect("couldn't insert com");

    // Client: Get the auth path in the list and use it to make a ZK proof
    let auth_path = global_list
        .get_auth_path(first_free_idx, &com)
        .expect("couldn't get auth path");
    let opening = (cred, com_nonce);
    let membership_proof = auth_path
        .zk_prove(&mut rng, &pk, opening)
        .expect("couldn't compute ZK proof");

    // Observer: Verify proof wrt the issuance list
    let list_root = global_list.root();
    assert!(zk_verify(&vk, &list_root, &membership_proof).expect("couldn't verify proof"));
}
