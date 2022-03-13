use crate::params::HASH_LEN;

use serde::{de::Error as SError, Deserialize, Deserializer};
use sha2::{Digest, Sha256};

#[derive(Default, Deserialize)]
pub struct PassportDump {
    #[serde(deserialize_with = "bytes_from_b64")]
    pub(crate) dg1: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_b64")]
    pub(crate) dg2: Vec<u8>,
    #[serde(rename = "pre-econtent", deserialize_with = "bytes_from_b64")]
    pub(crate) pre_econtent: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_b64")]
    pub(crate) econtent: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_b64")]
    pub(crate) sig: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_b64")]
    pub(crate) cert: Vec<u8>,
    #[serde(rename = "digest-alg")]
    pub(crate) digest_alg: String,
    #[serde(rename = "sig-alg")]
    pub(crate) sig_alg: String,
}

impl PassportDump {
    pub(crate) fn econtent_hash(&self) -> [u8; HASH_LEN] {
        Sha256::digest(&self.econtent).into()
    }
}

// Tells serde how to deserialize bytes from base64
fn bytes_from_b64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let b64_str = String::deserialize(deserializer)?;
    base64::decode(b64_str.as_bytes()).map_err(|e| SError::custom(format!("{:?}", e)))
}

/// Prints all the information stored in a passport's machine-readable zone (MRZ), plus the hash of
/// the biometrics
impl std::fmt::Debug for PassportDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use crate::params::*;

        f.debug_struct("PassportDump")
            .field(
                "issuer",
                &String::from_utf8_lossy(&self.dg1[ISSUER_OFFSET..ISSUER_OFFSET + STATE_ID_LEN]),
            )
            .field(
                "name",
                &String::from_utf8_lossy(&self.dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN]),
            )
            .field(
                "document number",
                &String::from_utf8_lossy(
                    &self.dg1[DOCUMENT_NUMBER_OFFSET..DOCUMENT_NUMBER_OFFSET + DOCUMENT_NUMBER_LEN],
                ),
            )
            .field(
                "nationality",
                &String::from_utf8_lossy(
                    &self.dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN],
                ),
            )
            .field(
                "date of birth",
                &String::from_utf8_lossy(&self.dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN]),
            )
            .field(
                "expiry",
                &String::from_utf8_lossy(&self.dg1[EXPIRY_OFFSET..EXPIRY_OFFSET + DATE_LEN]),
            )
            .field(
                "biometrics hash",
                &format_args!("{:x}", Sha256::digest(&self.dg2)),
            )
            .finish()
    }
}
