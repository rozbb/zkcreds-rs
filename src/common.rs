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

/// The bytelength of our attribute strings
pub(crate) const ATTR_STRING_LEN: usize = 16;

#[derive(Clone)]
pub struct AttrString(pub [u8; ATTR_STRING_LEN]);

impl AttrString {
    pub fn gen<R: RngCore>(rng: &mut R) -> AttrString {
        let mut buf = [0u8; ATTR_STRING_LEN];
        rng.fill_bytes(&mut buf);

        AttrString(buf)
    }
}

impl ToBytes for AttrString {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}

// To serialize and deserialize an attribute string, just use the Vec<T> routines
impl CanonicalSerialize for AttrString {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.0).map_err(Into::into)
    }

    fn serialized_size(&self) -> usize {
        ATTR_STRING_LEN
    }
}

impl CanonicalDeserialize for AttrString {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; ATTR_STRING_LEN];
        reader.read_exact(&mut buf)?;

        Ok(AttrString(buf))
    }
}

pub struct AttrStringVar<ConstraintF: PrimeField>(Vec<UInt8<ConstraintF>>);

impl<ConstraintF> AllocVar<AttrString, ConstraintF> for AttrStringVar<ConstraintF>
where
    ConstraintF: PrimeField,
{
    fn new_variable<T: Borrow<AttrString>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns: Namespace<_> = cs.into();
        let cs = ns.cs();

        // Get the attribute string if it's defined. Transpose it to a Vec of Options
        let underlying_val = f().ok();
        let attrs: Option<&AttrString> = underlying_val.as_ref().map(|c| c.borrow());
        let opt_bytes: Vec<Option<u8>> = match attrs {
            None => vec![None; ATTR_STRING_LEN],
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

        Ok(AttrStringVar(byte_vars))
    }
}

impl<ConstraintF> ToBytesGadget<ConstraintF> for AttrStringVar<ConstraintF>
where
    ConstraintF: PrimeField,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.to_vec())
    }
}
