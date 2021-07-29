use ark_ff::{fields::PrimeField, ToBytes};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    uint8::UInt8,
    ToBytesGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    borrow::Borrow,
    io::{Read, Result as IoResult, Write},
    rand::RngCore,
};

/// A credential is a 128 bit bitstring
pub const CRED_SIZE: usize = 16;
#[derive(Clone, Default)]
pub struct Credential([u8; CRED_SIZE]);

impl Credential {
    pub fn gen<R: RngCore>(rng: &mut R) -> Credential {
        let mut buf = [0u8; CRED_SIZE];
        rng.fill_bytes(&mut buf);

        Credential(buf)
    }
}

impl ToBytes for Credential {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}

// To serialize and deserialize a credential, just use the Vec<T> routines
impl CanonicalSerialize for Credential {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.0).map_err(Into::into)
    }

    fn serialized_size(&self) -> usize {
        CRED_SIZE
    }
}

impl CanonicalDeserialize for Credential {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; CRED_SIZE];
        reader.read_exact(&mut buf)?;

        Ok(Credential(buf))
    }
}

pub struct CredentialVar<ConstraintF: PrimeField>(Vec<UInt8<ConstraintF>>);

impl<ConstraintF> AllocVar<Credential, ConstraintF> for CredentialVar<ConstraintF>
where
    ConstraintF: PrimeField,
{
    fn new_variable<T: Borrow<Credential>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns: Namespace<_> = cs.into();
        let cs = ns.cs();

        // Get the credential if it's defined. Transpose it to a Vec of Options
        let underlying_val = f().ok();
        let cred: Option<&Credential> = underlying_val.as_ref().map(|c| c.borrow());
        let opt_bytes: Vec<Option<u8>> = match cred {
            None => vec![None; CRED_SIZE],
            Some(c) => c.0.iter().map(|&b| Some(b)).collect(),
        };

        // Now witness all the bytes
        let byte_vars: Vec<UInt8<_>> = opt_bytes
            .into_iter()
            .map(|byte| {
                UInt8::new_variable(
                    cs.clone(),
                    || byte.ok_or(SynthesisError::AssignmentMissing),
                    mode,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CredentialVar(byte_vars))
    }
}

impl<ConstraintF> ToBytesGadget<ConstraintF> for CredentialVar<ConstraintF>
where
    ConstraintF: PrimeField,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.to_vec())
    }
}
