use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar},
    pred::PredicateChecker,
    utils::{BlsFr, BlsFrV, BLS12_POSEIDON_PARAMS},
};

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ec::{
    models::{twisted_edwards_extended, TEModelParameters as Parameters},
    ProjectiveCurve,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_ff::{Field, PrimeField, ToBytes, ToConstraintField, UniformRand};
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::ToBitsGadget,
    eq::EqGadget,
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::twisted_edwards,
    groups::CurveVar,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::rand::{CryptoRng, Rng, RngCore};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};

pub(crate) type JubjubVar = EdwardsVar;
pub(crate) type Jubjub = EdwardsProjective;

const SCHNORR_DOMAIN_SEP: &[u8] = b"psch";

/// This trait exposes the ability to retrieve affine coordinates from a curve point
pub trait GetAffineCoords {
    type OutputField;
    fn affine_coords(&self) -> Vec<Self::OutputField>;
}

impl<P> GetAffineCoords for twisted_edwards_extended::GroupProjective<P>
where
    P: Parameters,
{
    type OutputField = P::BaseField;

    // Convert to affine, then return coords
    fn affine_coords(&self) -> Vec<P::BaseField> {
        let a = twisted_edwards_extended::GroupAffine::<P>::from(*self);
        vec![a.x, a.y]
    }
}

impl<P, FV> GetAffineCoords for twisted_edwards::AffineVar<P, FV>
where
    P: Parameters,
    FV: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
    for<'a> &'a FV: FieldOpsBounds<'a, P::BaseField, FV>,
{
    type OutputField = FV;

    fn affine_coords(&self) -> Vec<FV> {
        vec![self.x.clone(), self.y.clone()]
    }
}

/// Converts an element of a curve's scalar field into an element of the base field
pub(crate) fn fr_to_fq<C, Fq>(x: <C as ProjectiveCurve>::ScalarField) -> Fq
where
    C: ProjectiveCurve<BaseField = Fq>,
    Fq: PrimeField,
{
    let mut x_bytes = Vec::new();
    x.write(&mut x_bytes).unwrap();
    Fq::read(&*x_bytes).unwrap()
}

/// Serializes the given value into a Vec<u8>
pub(crate) fn to_canonical_bytes(
    val: impl CanonicalSerialize,
) -> Result<Vec<u8>, SerializationError> {
    let mut buf = Vec::new();
    val.serialize(&mut buf)?;
    Ok(buf)
}

type JubjubFr = <Jubjub as ProjectiveCurve>::ScalarField;

#[derive(Clone)]
pub struct SchnorrPrivkey(JubjubFr);

#[derive(Clone, Default)]
pub struct SchnorrPubkey(pub(crate) Jubjub);

#[derive(Clone)]
pub(crate) struct SchnorrPubkeyVar(JubjubVar);

#[derive(Clone, Default)]
pub struct SchnorrSignature {
    /// Challenge
    e: JubjubFr,
    /// Response to challenge
    s: JubjubFr,
}

#[derive(Clone)]
pub(crate) struct SchnorrSignatureVar {
    /// Challenge
    e: BlsFrV,
    /// Response to challenge
    s: BlsFrV,
}

impl SchnorrSignatureVar {
    pub(crate) fn new_witness(
        cs: impl Into<Namespace<BlsFr>>,
        sig: &SchnorrSignature,
    ) -> Result<SchnorrSignatureVar, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        // Signatures are Jubjub scalars. In order to use them in the circuit we need to embed them
        // into the Jubjub's scalar field (which is at least as big as the Jubjub scalar field, so
        // this is injective)
        let lifted_s = fr_to_fq::<Jubjub, BlsFr>(sig.s);
        let lifted_e = fr_to_fq::<Jubjub, BlsFr>(sig.e);

        // Construct the lifted signature
        let s_var = BlsFrV::new_witness(ns!(cs, "sig s var"), || Ok(lifted_s))?;
        let e_var = BlsFrV::new_witness(ns!(cs, "sig e var"), || Ok(lifted_e))?;

        Ok(SchnorrSignatureVar { e: e_var, s: s_var })
    }
}

impl<'a> From<&'a SchnorrPrivkey> for SchnorrPubkey {
    fn from(privkey: &'a SchnorrPrivkey) -> SchnorrPubkey {
        // g^privkey is the pubkey
        let g = Jubjub::prime_subgroup_generator();
        let pubkey = g.mul(privkey.0.into_repr());
        SchnorrPubkey(pubkey)
    }
}

/// Computes a domain-separated digest just for Schnorr signing. Returns the hash H(r || msg)
fn schnorr_digest(r: Jubjub, msg: &BlsFr) -> BlsFr {
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
    let domain_sep = SCHNORR_DOMAIN_SEP.to_field_elements().unwrap()[0];
    let hash_input = &[vec![domain_sep], r.affine_coords(), vec![*msg]].concat();
    hasher.hash(&hash_input).unwrap()
}

/// Computes a domain-separated digest just for Schnorr signing
pub(crate) fn schnorr_digest_gadget(
    cs: &mut ConstraintSystemRef<BlsFr>,
    r: &JubjubVar,
    msg: &BlsFrV,
) -> Result<BlsFrV, SynthesisError> {
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
    let hasher_var = PoseidonGadget::from_native(cs, hasher)?;
    let domain_sep = BlsFrV::constant(SCHNORR_DOMAIN_SEP.to_field_elements().unwrap()[0]);
    let hash_input = [vec![domain_sep], r.affine_coords(), vec![msg.clone()]].concat();
    hasher_var.hash(&hash_input)
}

impl SchnorrPrivkey {
    pub(crate) fn gen<R: Rng + ?Sized + CryptoRng>(rng: &mut R) -> SchnorrPrivkey {
        SchnorrPrivkey(JubjubFr::rand(rng))
    }

    /// Signs the given message under `privkey`. Return value is `(s, e)` where (using sigma
    /// protocol terminology) `e` is the challenge and `s` is the response.
    pub(crate) fn sign<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &BlsFr,
    ) -> SchnorrSignature {
        // g is the public generator
        // k is the secret nonce
        // g^k is the commitment
        let g = Jubjub::prime_subgroup_generator();
        let k = JubjubFr::rand(rng);
        let com = g.mul(k.into_repr());

        // e is H(com || msg)
        let mut hash_input = com.affine_coords();
        hash_input.push(*msg);
        let digest = schnorr_digest(com, msg);

        // The hash function outputs a Jubjub base field element, which we can't use as a Jubjub
        // scalar. So we convert it to bytes and truncate it to as many bits as a ScalarField
        // element can hold
        let e = {
            let mut digest_bytes = to_canonical_bytes(digest).unwrap();

            // We only want the first floor(log2(p)) bits of e, where r is the prime order of the
            // scalar field. We do this by finding how many bytes are needed to represent r,
            // truncating e to that many bytes, and then bitmasking the most significant byte of e
            // to be less than the most significant byte of r.
            let r_bitlen = JubjubFr::size_in_bits();

            // Calculate the index of the most significant byte in a scalar field element. Then
            // truncate the digest to be precisely this length. The truncated bytes still might
            // exceed r, so we're gonna bitmask the most significant byte
            let r_msb_pos = (r_bitlen - 1) / 8;
            let truncated_bytes = &mut digest_bytes[..r_msb_pos + 1];

            // The bitlength of the most significant byte of r
            let r_msb_bitlen = ((r_bitlen - 1) % 8) + 1;
            // This bitmask will mask the most significant bit of the most significant byte of r
            let msb_bitmask = (1 << (r_msb_bitlen - 1)) - 1;

            // Apply the bitmask
            truncated_bytes[r_msb_pos] &= msb_bitmask;

            // The truncated bytes now represent an integer that's less than r. This cannot fail.
            JubjubFr::from_random_bytes(&*truncated_bytes)
                .expect("couldn't convert BaseField elem to ScalarField elem")
        };

        // s is k - e * privkey
        let s = k - (e * self.0);

        SchnorrSignature { e, s }
    }
}

impl SchnorrPubkeyVar {
    pub(crate) fn new_input(
        cs: impl Into<Namespace<BlsFr>>,
        pk: &SchnorrPubkey,
    ) -> Result<SchnorrPubkeyVar, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let aff_pk = pk.0.into_affine();
        JubjubVar::new_input(cs, || Ok(aff_pk)).map(SchnorrPubkeyVar)
    }

    /// Verifies the given (message, signature) pair under the given public key. All this is done in
    /// zero-knowledge.
    /// The signature is expected to have been embedded from (Fr, Fr) to (Fq, Fq). The reason we do
    /// this is because doing that map in ZK is cumbersome and unnecessary.
    pub fn verify(&self, msg: &BlsFrV, sig: &SchnorrSignatureVar) -> Result<(), SynthesisError> {
        let mut cs = self.0.cs().or(msg.cs()).or(sig.e.cs()).or(sig.s.cs());

        // Witness the group generator. This is the same across all signatures
        let g = Jubjub::prime_subgroup_generator();
        let gv = JubjubVar::new_constant(ns!(cs, "Jubjub gen"), g)?;

        // The signature is (s, e)
        // r is g^s pubkey^e
        let SchnorrSignatureVar { e, s } = sig;
        let r = {
            // Computs g^s
            let s_bits = s.to_bits_le()?;
            let g_s = gv.scalar_mul_le(s_bits.iter())?;
            // Compute pubkey^e
            let e_bits = e.to_bits_le()?;
            let pubkey_e = self.0.scalar_mul_le(e_bits.iter())?;

            // Add them
            g_s + pubkey_e
        };

        // e' is H(r || msg). This should be equal to the given e, up to Fr::size() many bits
        let e_prime = schnorr_digest_gadget(&mut cs, &r, msg)?;

        // Show that e' and e agree for all the bits up to the bitlength of the scalar field's
        // modulus. We check the truncation because we have to use the truncation of e as a scalar
        // field element (since e is naturally a base field element and too big to be a scalar
        // field element).
        let e_prime_bits = e_prime.to_bits_le()?;
        let e_bits = e.to_bits_le()?;
        let scalar_mod_bitlen = JubjubFr::size_in_bits();

        // Assert that this this verified successfully
        e_prime_bits[..scalar_mod_bitlen - 1].enforce_equal(&e_bits[..scalar_mod_bitlen - 1])
    }
}

#[derive(Clone)]
pub struct SigChecker {
    // Public inputs //
    pub pubkey: SchnorrPubkey,

    // Private inputs //
    pub privkey: SchnorrPrivkey,
    pub sig: SchnorrSignature,
}

impl<A, AV, AC, ACG> PredicateChecker<BlsFr, A, AV, AC, ACG> for SigChecker
where
    A: AccountableAttrs<BlsFr, AC>,
    AV: AccountableAttrsVar<BlsFr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, BlsFr, OutputVar = BlsFrV>,
    AC::Output: ToConstraintField<BlsFr>,
{
    /// Returns whether or not the predicate was satisfied
    fn pred(
        self,
        cs: ConstraintSystemRef<BlsFr>,
        com: &BlsFrV,
        attrs: &AV,
    ) -> Result<(), SynthesisError> {
        let sig = SchnorrSignatureVar::new_witness(ns!(cs, "sig"), &self.sig)?;
        let pubkey = SchnorrPubkeyVar::new_input(ns!(cs, "pubkey"), &self.pubkey)?;
        pubkey.verify(com, &sig)
    }

    /// This outputs the field elements corresponding to the public inputs of this predicate.
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<BlsFr> {
        self.pubkey.0.to_field_elements().unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_ff::UniformRand;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    // Just checks that Schnorr signing doesn't panic
    #[test]
    fn test_sign() {
        // Try signing 100 times with different randomness. There used to be an issue where the
        // value of e was invalid and it would panic some of the time. So now we run the test a lot
        // of times.
        for seed in 0..100 {
            // Make a random privkey and message
            let mut rng = StdRng::seed_from_u64(seed);
            let privkey = SchnorrPrivkey::gen(&mut rng);
            let msg = BlsFr::rand(&mut rng);

            // Sign the random message under the random privkey
            privkey.sign(&mut rng, &msg);
        }
    }
}
