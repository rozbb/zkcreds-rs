/// Stores a subset of the info found in data groups 1 and 2 of a passport
struct PersonalInfo {
    nonce: ComNonce,
    rate_limit_key: FieldElem,
    nationality: [u8; STATE_ID_LEN],
    name: [u8; NAME_LEN],
    dob: u32,
    passport_expiry: u32,
    biometrics: Biometrics,
}

/// Stores a subset of the info found in data groups 1 and 2 of a passport
struct PersonalInfoVar {
    nonce: ComNonceVar<PassportComScheme, PassportComSchemeG, FieldElem>,
    rate_limit_key: FpVar<FieldElem>,
    nationality: Bytestring<FieldElem>,
    name: Bytestring<FieldElem>,
    dob: FpVar<FieldElem>,
    passport_expiry: FpVar<FieldElem>,
    biometric_hash: Bytestring<FieldElem>,
}

// Make PersonalInfo an Attrs type, i.e., something that can be committed to
impl Attrs<FieldElem, PassportComScheme> for PersonalInfo {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        // DOB bytes need to match the PersonalInfoVar version, which is an FpVar. Convert to FieldElem
        // before serializing
        let dob = FieldElem::from(self.dob);
        let passport_expiry = FieldElem::from(self.passport_expiry);
        let biometric_hash = self.biometrics.hash();
        to_bytes![
            self.seed,
            self.nationality,
            self.name,
            dob,
            passport_expiry,
            biometric_hash
        ]
        .unwrap()
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

// Make PersonalInfo an AccountableAttrs type, i.e., one that can form pseudonyms and rate-limit
// tokens
impl AccountableAttrs<FieldElem, PassportComScheme> for PersonalInfo {
    type Id = Vec<u8>;
    type Seed = FieldElem;

    fn get_id(&self) -> Self::Id {
        self.name.to_vec()
    }

    fn get_seed(&self) -> Self::Seed {
        self.seed
    }
}

// Similarly, make PersonalInfoVar something that can be committed. First, define a way to get its
// nonce:
impl AttrsVar for PersonalInfoVar {
    fn get_com_nonce(&self) -> Result<ComNonceVar, SynthesisError> {
        Ok(self.nonce.clone())
    }
}
// Second, define a way to serialize a PersonalInfoVar
impl ToBytesGadget<FieldElem> for PersonalInfoVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<FieldElem>>, SynthesisError> {
        Ok([
            self.seed.to_bytes()?,
            self.nationality.0.to_bytes()?,
            self.name.0.to_bytes()?,
            self.dob.to_bytes()?,
            self.passport_expiry.to_bytes()?,
            self.biometric_hash.0.to_bytes()?,
        ]
        .concat())
    }
}

// Again, as above, make PersonalInfoVar something that can form pseudonyms and rate-limit tokens
impl AccountableAttrsVar for PersonalInfoVar {
    type Id = Bytestring<FieldElem>;
    type Seed = FpVar<FieldElem>;

    fn get_id(&self) -> Result<Bytestring<FieldElem>, SynthesisError> {
        Ok(self.name.clone())
    }

    fn get_seed(&self) -> Result<FpVar<FieldElem>, SynthesisError> {
        Ok(self.seed.clone())
    }
}

// This is a bit messy. Make PersonalInfoVar allocatable. That is, define a way to construct a
// PeronsalInfoVar from a PersonalInfo. This is tedious, but not hard.
impl AllocVar<PersonalInfo, FieldElem> for PersonalInfoVar {
    // Allocates a vector of UInt8s. This panics if `f()` is `Err`, since we don't know how many
    // bytes to allocate
    fn new_variable<T: Borrow<PersonalInfo>>(
        cs: impl Into<Namespace<FieldElem>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_attrs = f();

        // Make placeholder content if native_attrs is empty
        let default_info = PersonalInfo::default();

        // Unpack the given attributes
        let PersonalInfo {
            ref nonce,
            ref rate_limit_key,
            ref nationality,
            ref name,
            ref dob,
            ref passport_expiry,
            ref biometrics,
        } = native_attrs
            .as_ref()
            .map(Borrow::borrow)
            .unwrap_or(&default_info);

        let biometric_hash = biometrics.hash().to_vec();

        // Witness the nonce
        let nonce = ComNonceVar::<PassportComScheme, PassportComSchemeG, FieldElem>::new_variable(
            ns!(cs, "nonce"),
            || Ok(nonce),
            mode,
        )?;

        // Witness all the other variables
        let seed = FpVar::<FieldElem>::new_variable(ns!(cs, "seed"), || Ok(seed), mode)?;
        let nationality =
            Bytestring::new_variable(ns!(cs, "nationality"), || Ok(nationality.to_vec()), mode)?;
        let name = Bytestring::new_variable(ns!(cs, "name"), || Ok(name.to_vec()), mode)?;
        let dob =
            FpVar::<FieldElem>::new_variable(ns!(cs, "dob"), || Ok(FieldElem::from(*dob)), mode)?;
        let passport_expiry = FpVar::<FieldElem>::new_variable(
            ns!(cs, "passport expiry"),
            || Ok(FieldElem::from(*passport_expiry)),
            mode,
        )?;
        let biometric_hash =
            Bytestring::new_variable(ns!(cs, "biometric_hash"), || Ok(biometric_hash), mode)?;

        // Return the witnessed values
        Ok(PersonalInfoVar {
            nonce,
            rate_limit_key,
            nationality,
            name,
            dob,
            passport_expiry,
            biometric_hash,
        })
    }
}
