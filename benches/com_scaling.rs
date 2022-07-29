use zkcreds::utils::{Bls12PoseidonCommitter, Bls12PoseidonCrh};

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;

pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;

#[derive(Copy, Clone)]
pub struct EmptyPred;

type TestTreeH = Bls12PoseidonCrh;
type TestTreeHG = Bls12PoseidonCrh;
type TestComScheme = Bls12PoseidonCommitter;
type TestComSchemeG = Bls12PoseidonCommitter;

macro_rules! make_show_bench {
    ($num_bytes:expr, $bench_name:ident) => {
        pub mod $bench_name {
            use super::*;

            use zkcreds::{
                attrs::{Attrs, AttrsVar},
                pred::{gen_pred_crs, prove_birth, PredicateChecker},
                utils::ComNonce,
                ComParam, ComParamVar,
            };

            use ark_crypto_primitives::commitment::CommitmentScheme;
            use ark_ff::UniformRand;
            use ark_r1cs_std::{alloc::AllocVar, bits::ToBytesGadget, uint8::UInt8, R1CSVar};
            use ark_relations::{
                ns,
                r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
            };
            use ark_std::{
                io::Write,
                rand::{rngs::StdRng, Rng, SeedableRng},
            };
            use criterion::Criterion;
            use lazy_static::lazy_static;

            lazy_static! {
                static ref BIG_COM_PARAM: <TestComScheme as CommitmentScheme>::Parameters = {
                    let mut rng = {
                        let mut seed = [0u8; 32];
                        let mut writer = &mut seed[..];
                        writer.write_all(b"zkcreds-commitment-param").unwrap();
                        StdRng::from_seed(seed)
                    };
                    TestComScheme::setup(&mut rng).unwrap()
                };
            }

            #[derive(Clone, Default)]
            struct FillerAttrs {
                nonce: ComNonce,
                num_bytes: usize,
            }

            #[derive(Clone)]
            struct FillerAttrsVar {
                nonce: ComNonce,
                bytes: Vec<UInt8<Fr>>,
                cs: ConstraintSystemRef<Fr>,
            }

            impl FillerAttrs {
                fn new<R: Rng>(rng: &mut R, num_bytes: usize) -> FillerAttrs {
                    let nonce = ComNonce::rand(rng);
                    FillerAttrs { nonce, num_bytes }
                }
            }

            impl Attrs<Fr, TestComScheme> for FillerAttrs {
                /// Serializes the attrs into bytes
                fn to_bytes(&self) -> Vec<u8> {
                    vec![0u8; self.num_bytes]
                }

                fn get_com_param(&self) -> &ComParam<TestComScheme> {
                    &*BIG_COM_PARAM
                }

                fn get_com_nonce(&self) -> &ComNonce {
                    &self.nonce
                }
            }

            impl PredicateChecker<Fr, FillerAttrs, FillerAttrsVar, TestComScheme, TestComSchemeG>
                for EmptyPred
            {
                fn pred(
                    self,
                    _cs: ConstraintSystemRef<Fr>,
                    _attrs: &FillerAttrsVar,
                ) -> Result<(), SynthesisError> {
                    Ok(())
                }

                fn public_inputs(&self) -> Vec<Fr> {
                    Vec::new()
                }
            }

            impl ToBytesGadget<Fr> for FillerAttrsVar {
                fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
                    Ok(self.bytes.clone())
                }
            }

            impl AttrsVar<Fr, FillerAttrs, TestComScheme, TestComSchemeG> for FillerAttrsVar {
                fn cs(&self) -> ConstraintSystemRef<Fr> {
                    self.cs.clone()
                }

                fn witness_attrs(
                    cs: impl Into<Namespace<Fr>>,
                    attrs: &FillerAttrs,
                ) -> Result<Self, SynthesisError> {
                    let cs = cs.into().cs();
                    let nonce = attrs.nonce.clone();

                    let num_bytes = attrs.num_bytes;
                    let bytes: Vec<UInt8<Fr>> = (0..num_bytes)
                        .map(|_| UInt8::new_witness(ns!(cs, "byte"), || Ok(0u8)))
                        .collect::<Result<Vec<_>, _>>()?;

                    Ok(FillerAttrsVar { nonce, bytes, cs })
                }

                fn get_com_param(
                    &self,
                ) -> Result<ComParamVar<TestComScheme, TestComSchemeG, Fr>, SynthesisError>
                {
                    let cs = self.bytes.cs();
                    ComParamVar::<_, TestComSchemeG, _>::new_constant(cs, &*BIG_COM_PARAM)
                }

                fn get_com_nonce(&self) -> &ComNonce {
                    &self.nonce
                }
            }

            // This benchmarks the linkage functions as the number of predicates increases
            pub fn $bench_name(c: &mut Criterion) {
                let mut rng = ark_std::test_rng();

                let checker = EmptyPred;
                let pk =
                    gen_pred_crs::<_, _, E, _, _, _, _, TestTreeH, TestTreeHG>(&mut rng, checker)
                        .unwrap();
                let attrs = FillerAttrs::new(&mut rng, $num_bytes);

                c.bench_function(
                    &format!("Proving empty show [attr_size={}]", $num_bytes),
                    |b| b.iter(|| prove_birth(&mut rng, &pk, checker, attrs.clone()).unwrap()),
                );
            }
        }
    };
}

make_show_bench!(0, bench_pred_proof_0);
make_show_bench!(16, bench_pred_proof_16);
make_show_bench!(32, bench_pred_proof_32);
make_show_bench!(48, bench_pred_proof_48);
make_show_bench!(64, bench_pred_proof_64);
make_show_bench!(80, bench_pred_proof_80);
make_show_bench!(96, bench_pred_proof_96);
make_show_bench!(112, bench_pred_proof_112);
make_show_bench!(128, bench_pred_proof_128);
make_show_bench!(144, bench_pred_proof_144);
make_show_bench!(160, bench_pred_proof_160);
make_show_bench!(176, bench_pred_proof_176);
make_show_bench!(192, bench_pred_proof_192);
make_show_bench!(208, bench_pred_proof_208);
make_show_bench!(224, bench_pred_proof_224);
make_show_bench!(240, bench_pred_proof_240);
make_show_bench!(256, bench_pred_proof_256);
