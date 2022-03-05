use serde::{de::Error as SError, Deserialize, Deserializer};

#[derive(Default, Debug, Deserialize)]
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

/// Prints all the information stored in a passport's machine-readable zone (MRZ)
pub(crate) fn print_mrz_info(dump: &PassportDump) {
    use crate::params::*;

    eprintln!(
        "Issuer == {}",
        String::from_utf8_lossy(&dump.dg1[ISSUER_OFFSET..ISSUER_OFFSET + STATE_ID_LEN])
    );
    eprintln!(
        "Name == {}",
        String::from_utf8_lossy(&dump.dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN])
    );
    eprintln!(
        "Doc # == {}",
        String::from_utf8_lossy(
            &dump.dg1[DOCUMENT_NUMBER_OFFSET..DOCUMENT_NUMBER_OFFSET + DOCUMENT_NUMBER_LEN]
        )
    );
    eprintln!(
        "Nationality == {}",
        String::from_utf8_lossy(&dump.dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN])
    );
    eprintln!(
        "DOB == {}",
        String::from_utf8_lossy(&dump.dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN])
    );
    eprintln!(
        "Expiry == {}",
        String::from_utf8_lossy(&dump.dg1[EXPIRY_OFFSET..EXPIRY_OFFSET + DATE_LEN])
    );
}

// Tells serde how to deserialize bytes from base64
fn bytes_from_b64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let b64_str = String::deserialize(deserializer)?;
    base64::decode(b64_str.as_bytes()).map_err(|e| SError::custom(format!("{:?}", e)))
}
