use crate::microbenches::monolithic_proof::{
    gen_monolithic_crs, prove_monolithic, verify_monolithic,
};

use core::borrow::Borrow;

use zkcreds::{
    attrs::{
        AccountableAttrs as AccountableAttrsTrait, AccountableAttrsVar as AccountableAttrsVarTrait,
        Attrs as AttrsTrait, AttrsVar as AttrsVarTrait,
    },
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree},
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    poseidon_utils::{setup_poseidon_params, Bls12PoseidonCommitter, Bls12PoseidonCrh, ComNonce},
    pred::{gen_pred_crs, prove_pred},
    revealing_multishow::{MultishowableAttrs, RevealingMultishowChecker},
    zk_utils::UnitVar,
    ComNonceVar, ComParam, ComParamVar,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{commitment::CommitmentScheme, crh::TwoToOneCRH};
use ark_ec::PairingEngine;
use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsParameters};
use ark_ff::{to_bytes, UniformRand};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::{
    io::Write,
    rand::{rngs::StdRng, Rng, SeedableRng},
};
use arkworks_utils::Curve;
use criterion::Criterion;
use lazy_static::lazy_static;
use linkg16::groth16;

const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);
const POSEIDON_WIDTH: u8 = 5;

type E = Bls12_381;
type Fr = <E as PairingEngine>::Fr;

type ComScheme = Bls12PoseidonCommitter;
type ComSchemeG = Bls12PoseidonCommitter;
type TreeH = Bls12PoseidonCrh;
type TreeHG = Bls12PoseidonCrh;

#[derive(Clone, Default)]
struct Attrs {
    nonce: ComNonce,
    seed: Fr,
    id: u8,
}

#[derive(Clone)]
struct AttrsVar {
    nonce: ComNonce,
    seed: FpVar<Fr>,
    id: UInt8<Fr>,
}

impl Attrs {
    fn new<R: Rng>(rng: &mut R) -> Attrs {
        let nonce = ComNonce::rand(rng);
        let seed = Fr::rand(rng);
        let id = u8::rand(rng);
        Attrs { nonce, seed, id }
    }
}

impl AttrsTrait<Fr, ComScheme> for Attrs {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes![self.seed, self.id].unwrap()
    }

    fn get_com_param(&self) -> &ComParam<ComScheme> {
        &()
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsTrait<Fr, ComScheme> for Attrs {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Self::Id {
        vec![self.id]
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for AttrsVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([self.seed.to_bytes()?, vec![self.id.clone()]].concat())
    }
}

impl AttrsVarTrait<Fr, Attrs, ComScheme, ComSchemeG> for AttrsVar {
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed.cs().or(self.id.cs())
    }

    fn witness_attrs(cs: impl Into<Namespace<Fr>>, attrs: &Attrs) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let nonce = attrs.nonce.clone();
        let seed = FpVar::<Fr>::new_witness(ns!(cs, "seed"), || Ok(attrs.seed))?;
        let id = UInt8::<Fr>::new_witness(ns!(cs, "id"), || Ok(attrs.id))?;

        Ok(AttrsVar { nonce, seed, id })
    }

    fn get_com_param(&self) -> Result<ComParamVar<ComScheme, ComSchemeG, Fr>, SynthesisError> {
        Ok(UnitVar::default())
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVarTrait<Fr, Attrs, ComScheme, ComSchemeG> for AttrsVar {
    type Id = Vec<UInt8<Fr>>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Self::Id, SynthesisError> {
        Ok(vec![self.id.clone()])
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}

// This benchmarks the linkage functions as the number of predicates increases
pub fn bench_revealing_multishow(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    //
    // Generate CRSs
    //

    let epoch = 5;
    let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
    let max_num_presentations: u16 = 128;
    let placeholder_checker = RevealingMultishowChecker {
        params: params.clone(),
        ..Default::default()
    };
    let multishow_pk =
        gen_pred_crs::<_, _, E, _, _, _, _, TreeH, TreeHG>(&mut rng, placeholder_checker).unwrap();
    let multishow_vk = multishow_pk.prepare_verifying_key();
    let tree_pk = gen_tree_memb_crs::<_, E, Attrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng,
        (),
        TREE_HEIGHT,
    )
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();
    let forest_pk = gen_forest_memb_crs::<_, E, Attrs, ComScheme, ComSchemeG, TreeH, TreeHG>(
        &mut rng, NUM_TREES,
    )
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    //
    // User makes a cred and computes the token
    //

    let attrs = Attrs::new(&mut rng);
    let cred = attrs.commit();
    let nonce = Fr::rand(&mut rng);
    let ctr: u16 = 1;
    let token = attrs
        .compute_presentation_token(params.clone(), epoch, ctr, nonce)
        .unwrap();

    // Create the tree proof
    let mut tree = ComTree::empty((), TREE_HEIGHT);
    let auth_path = tree.insert(0, &cred);
    c.bench_function("Revealing multishow: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(&mut rng, &tree_pk, &(), cred)
                .unwrap()
        })
    });
    let tree_proof = auth_path
        .prove_membership(&mut rng, &tree_pk, &(), cred)
        .unwrap();

    // Create forest proof
    let root = tree.root();
    let mut roots = ComForestRoots::new(NUM_TREES - 1);
    roots.roots.push(root);
    c.bench_function("Revealing multishow: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(&mut rng, &forest_pk, root, cred)
                .unwrap()
        })
    });
    let forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, root, cred)
        .unwrap();

    // Create revealing multishow proof
    let multishow_checker = RevealingMultishowChecker {
        token,
        epoch,
        nonce,
        max_num_presentations,
        ctr,
        params,
    };
    c.bench_function("Revealing multishow: proving multishow", |b| {
        b.iter(|| {
            prove_pred(
                &mut rng,
                &multishow_pk,
                multishow_checker.clone(),
                attrs.clone(),
                &auth_path,
            )
            .unwrap()
        })
    });
    let multishow_proof = prove_pred(
        &mut rng,
        &multishow_pk,
        multishow_checker.clone(),
        attrs.clone(),
        &auth_path,
    )
    .unwrap();

    let monolithic_pk: groth16::ProvingKey<E> =
        gen_monolithic_crs::<_, E, Attrs, AttrsVar, ComScheme, ComSchemeG, TreeH, TreeHG, _>(
            &mut rng,
            (),
            TREE_HEIGHT,
            NUM_TREES,
            multishow_checker.clone(),
        )
        .unwrap();
    let monolithic_vk = monolithic_pk.verifying_key();
    c.bench_function("Revealing multishow: proving monolithic", |b| {
        b.iter(|| {
            prove_monolithic::<_, _, _, AttrsVar, _, ComSchemeG, _, TreeHG, _>(
                &mut rng,
                &monolithic_pk,
                &(),
                &roots,
                &auth_path,
                attrs.clone(),
                multishow_checker.clone(),
            )
            .unwrap()
        })
    });
    let proof = prove_monolithic::<_, _, _, AttrsVar, _, ComSchemeG, _, TreeHG, _>(
        &mut rng,
        &monolithic_pk,
        &(),
        &roots,
        &auth_path,
        attrs.clone(),
        multishow_checker.clone(),
    )
    .unwrap();
    c.bench_function("Revealing multishow: verifying monolithic", |b| {
        b.iter(|| {
            assert!(verify_monolithic::<_, Attrs, AttrsVar, _, _, _, TreeHG, _>(
                &monolithic_vk,
                &roots,
                &proof,
                multishow_checker.clone()
            )
            .unwrap())
        })
    });

    // Prepare revealing multishow inputs
    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&multishow_vk, &multishow_checker);

    let link_vk = LinkVerifyingKey::<_, _, AttrsVar, _, _, _, _> {
        pred_inputs,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk,
        tree_verif_key: tree_vk,
        pred_verif_keys: vec![multishow_vk],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: root,
        forest_proof,
        tree_proof,
        pred_proofs: vec![multishow_proof],
        vk: link_vk.clone(),
    };
    c.bench_function("Revealing multishow: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let link_proof = link_proofs(&mut rng, &link_ctx);
    crate::util::record_size("Revealing multishow", &link_proof);

    c.bench_function("Revealing multishow: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });
}
