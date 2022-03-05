use crate::passport_dump::PassportDump;
use rsa::{padding::PaddingScheme, pkcs8::FromPublicKey, Hash, PublicKey, RsaPublicKey};
use x509_parser::parse_x509_certificate;

// A PKCS#8 encoding of the US State Department's passport signing pubkey. This was a pain to
// extract. See the below link for instructions
// https://github.com/AndyQ/NFCPassportReader/tree/master/scripts
const USA_PUBKEY: &str = "\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt71UyAr9GvihRSGIDeH
oDc0CjFsmMP92+42QAIai2r4A+crqvpx7bJJvE4ZYrhniVmDim+Ce6pheRzFKmTo
2srL46x3gflmyttEASqJbSP4+T4NlbzrxDHl8jPmIKvRIvwtbza56o9leOEWkCzW
7Sfwo10EvcjUamfMM4XKi+/bRZo44jG5bTx8jpjPCBKwm5RbfTpwhLHWmYDyTV0q
8CPartxl0pxt0jp87VQB3vs+cO3NYpBK0QOlO0LAwkTwetVy2O3YEswO36vn/ldt
TADYn/CxmJVqhyL98MMhUuvLwopdpjcWuwXRThCpSbcvBNYTYmI/rQ0DgmFq/v7z
1wIDAQAB
-----END PUBLIC KEY-----";

pub struct IssuerPubkey(RsaPublicKey);

pub fn load_usa_pubkey() -> IssuerPubkey {
    let pubkey = RsaPublicKey::from_public_key_pem(USA_PUBKEY).unwrap();
    IssuerPubkey(pubkey)
}

pub fn load_pubkey_from_dump(dump: &PassportDump) -> IssuerPubkey {
    let cert = (parse_x509_certificate(&dump.cert).unwrap()).1;
    let pubkey = RsaPublicKey::from_public_key_der(cert.public_key().raw).unwrap();
    IssuerPubkey(pubkey)
}

impl IssuerPubkey {
    #[must_use]
    pub fn verify(&self, sig: &[u8], hash: &[u8]) -> bool {
        self.0
            .verify(
                PaddingScheme::PKCS1v15Sign {
                    hash: Some(Hash::SHA2_256),
                },
                hash,
                sig,
            )
            .is_ok()
    }
}
