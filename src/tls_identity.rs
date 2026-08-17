use std::{collections::HashSet, fs, io, path::Path};

use crate::{
    asn1,
    crypto::wipe_bytes,
    p256::{Scalar, p256_generator_multiply},
};

#[derive(Clone)]
pub struct TlsIdentity {
    certificate_chain: Vec<Vec<u8>>,
    signing_key: Scalar,
    dns_names: Vec<String>,
}

impl TlsIdentity {
    pub fn load_pem_files(
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let certificate_pem = fs::read_to_string(certificate_path)?;

        let certificate_chain = asn1::decode_x509_certificate_chain_pem(&certificate_pem)
            .map_err(|error| invalid_data(error.to_string()))?;

        let leaf = asn1::parse_x509_certificate_der(&certificate_chain[0])
            .map_err(|error| invalid_data(error.to_string()))?;

        for certificate in &certificate_chain[1..] {
            asn1::parse_x509_certificate_der(certificate)
                .map_err(|error| invalid_data(error.to_string()))?;
        }

        if leaf.dns_names.is_empty() {
            return Err(invalid_data(
                "TLS leaf certificate contains no DNS subjectAltName identities",
            ));
        }

        let mut private_key_pem = fs::read(private_key_path)?;

        let signing_key_result = std::str::from_utf8(&private_key_pem)
            .map_err(|_| invalid_data("TLS private key PEM is not valid UTF-8"))
            .and_then(|private_key_pem| {
                asn1::decode_p256_sec1_private_key_pem(private_key_pem)
                    .map_err(|error| invalid_data(error.to_string()))
            });

        wipe_bytes(&mut private_key_pem);

        let signing_key = signing_key_result?;

        let expected_public_key = p256_generator_multiply(signing_key);

        if leaf.public_key.p256_public_key != Some(expected_public_key) {
            return Err(invalid_data(
                "TLS leaf certificate public key does not match the supplied private key",
            ));
        }

        Ok(Self {
            certificate_chain,
            signing_key,
            dns_names: leaf.dns_names,
        })
    }

    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    pub fn signing_key(&self) -> Scalar {
        self.signing_key
    }

    pub fn dns_names(&self) -> &[String] {
        &self.dns_names
    }

    pub fn matches_server_name(&self, server_name: &str) -> bool {
        self.dns_names
            .iter()
            .any(|dns_name| dns_name_matches(dns_name, server_name))
    }

    fn matches_server_name_exactly(&self, server_name: &str) -> bool {
        self.dns_names.iter().any(|dns_name| {
            !dns_name.starts_with("*.") && dns_name.eq_ignore_ascii_case(server_name)
        })
    }
}

#[derive(Clone)]
pub struct TlsIdentityStore {
    identities: Vec<TlsIdentity>,
}

impl TlsIdentityStore {
    pub fn new(identities: Vec<TlsIdentity>) -> io::Result<Self> {
        if identities.is_empty() {
            return Err(invalid_input(
                "TLS identity store must contain at least one identity",
            ));
        }

        let mut presented_names = HashSet::new();

        for identity in &identities {
            for dns_name in identity.dns_names() {
                let normalized = dns_name.to_ascii_lowercase();

                if !presented_names.insert(normalized.clone()) {
                    return Err(invalid_input(format!(
                        "multiple TLS identities claim DNS name {normalized}"
                    )));
                }
            }
        }

        Ok(Self { identities })
    }

    pub fn identities(&self) -> &[TlsIdentity] {
        &self.identities
    }

    pub fn select(&self, server_name: &str) -> Option<&TlsIdentity> {
        self.identities
            .iter()
            .find(|identity| identity.matches_server_name_exactly(server_name))
            .or_else(|| {
                self.identities
                    .iter()
                    .find(|identity| identity.matches_server_name(server_name))
            })
    }
}

fn dns_name_matches(presented_name: &str, server_name: &str) -> bool {
    if server_name.is_empty() || !server_name.is_ascii() || server_name.ends_with('.') {
        return false;
    }

    if presented_name.eq_ignore_ascii_case(server_name) {
        return true;
    }

    let Some(suffix) = presented_name.strip_prefix("*.") else {
        return false;
    };

    let Some((leftmost_label, server_suffix)) = server_name.split_once('.') else {
        return false;
    };

    !leftmost_label.is_empty() && server_suffix.eq_ignore_ascii_case(suffix)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::{TlsIdentity, TlsIdentityStore, dns_name_matches};

    use crate::p256::{Scalar, Uint256};

    fn test_identity(dns_names: &[&str], private_scalar: u64) -> TlsIdentity {
        TlsIdentity {
            certificate_chain: vec![vec![private_scalar as u8]],
            signing_key: Scalar::new(Uint256::from_limbs([private_scalar, 0, 0, 0])),
            dns_names: dns_names
                .iter()
                .map(|dns_name| (*dns_name).to_owned())
                .collect(),
        }
    }

    #[test]
    fn exact_dns_identity_matches_case_insensitively() {
        assert!(dns_name_matches("www.example.com", "WWW.Example.Com"));

        assert!(!dns_name_matches("www.example.com", "api.example.com"));
    }

    #[test]
    fn wildcard_matches_exactly_one_leftmost_label() {
        assert!(dns_name_matches("*.example.com", "api.example.com"));

        assert!(!dns_name_matches("*.example.com", "deep.api.example.com"));

        assert!(!dns_name_matches("*.example.com", "example.com"));
    }

    #[test]
    fn identity_store_prefers_exact_name_over_wildcard() {
        let wildcard = test_identity(&["*.example.com"], 1);
        let exact = test_identity(&["www.example.com"], 2);

        let exact_key = exact.signing_key();

        let store = TlsIdentityStore::new(vec![wildcard, exact]).unwrap();

        assert_eq!(
            store
                .select("www.example.com")
                .expect("exact identity should be selected")
                .signing_key(),
            exact_key
        );
    }

    #[test]
    fn identity_store_keeps_multiple_certificates_in_memory() {
        let first = test_identity(&["one.example.com"], 1);
        let second = test_identity(&["two.example.com"], 2);

        let store = TlsIdentityStore::new(vec![first, second]).unwrap();

        assert_eq!(store.identities().len(), 2);
        assert!(store.select("one.example.com").is_some());
        assert!(store.select("two.example.com").is_some());
        assert!(store.select("unknown.example.com").is_none());
    }

    #[test]
    fn identity_store_rejects_duplicate_presented_names() {
        let first = test_identity(&["www.example.com"], 1);
        let second = test_identity(&["WWW.EXAMPLE.COM"], 2);

        assert!(TlsIdentityStore::new(vec![first, second]).is_err());
    }
}
