use super::api::Client;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rsa::{hash::Hash, padding::PaddingScheme, PublicKeyParts, RSAPrivateKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn kw(name: &str) -> String {
    format!("identity.mozilla.com/picl/v1/{}", name)
}

#[derive(Serialize)]
struct Assertion<'a> {
    exp: u128,
    aud: &'a str,
}

pub async fn get_browserid_assertion(client: &Client, session_token: &str) -> String {
    let mut derived_from_session_token = [0u8; 64];
    // TODO: give user feedback about slow key generation
    let rsa_private_key = RSAPrivateKey::new(&mut OsRng, 2048).unwrap();
    Hkdf::<Sha256>::new(None, &hex::decode(session_token).unwrap())
        .expand(
            kw("sessionToken").as_bytes(),
            &mut derived_from_session_token,
        )
        .unwrap();
    let certificate = client
        .certificate_sign(
            &rsa_private_key.n().to_str_radix(10),
            &rsa_private_key.e().to_str_radix(10),
            &hawk::Credentials {
                id: hex::encode(&derived_from_session_token[0..32]),
                key: hawk::Key::new(
                    &derived_from_session_token[32..64],
                    hawk::DigestAlgorithm::Sha256,
                )
                .unwrap(),
            },
        )
        .await;

    let signed_data = format!(
        "{}.{}",
        base64::encode_config("{\"alg\": \"RS256\"}", base64::URL_SAFE_NO_PAD),
        base64::encode_config(
            &serde_json::to_string(&Assertion {
                // TODO: Calculate time skew
                // TODO: Make exp match with other exp (in call to certificate sign)
                exp: (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                    + Duration::from_secs(60 * 10))
                .as_millis(),
                aud: "https://token.services.mozilla.com/"
            })
            .unwrap(),
            base64::URL_SAFE_NO_PAD
        ),
    );

    let assertion = format!(
        "{}.{}",
        &signed_data,
        base64::encode_config(
            rsa_private_key
                .sign(
                    PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    },
                    &Sha256::new().chain(&signed_data).finalize(),
                )
                .unwrap(),
            base64::URL_SAFE_NO_PAD,
        )
    );

    format!("{}~{}", certificate.cert, assertion)
}
