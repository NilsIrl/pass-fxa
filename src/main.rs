use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use prs_lib::{crypto::IsContext, Store};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env::VarError,
    io::{self, Write},
};

mod api;
mod crypto;

use api::{Client, Verification};
use crypto::kw;

#[derive(Deserialize)]
struct CryptoKeyRecord {
    default: Vec<String>,
}

fn kwe(name: &str, email: &str) -> String {
    format!("{}:{}", kw(name), email)
}

fn xor(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

async fn login(client: &Client, store: &Store) {
    // TODO: smh be more legit, I always get hit with the request blocked
    // TODO: change api to accept &str
    let firefox_credentials;
    let firefox_matches = store.secrets(Some("firefox.com".to_string()));
    match firefox_matches.len() {
        0 => panic!("Could not find Firefox Account credentials."),
        1 => {
            firefox_credentials = &firefox_matches[0];
        }
        _ => panic!(
            "Ambiguous Firefox Account credential locations: {:?}",
            firefox_matches
        ),
    }

    let mut pass_context = prs_lib::crypto::context(prs_lib::crypto::PROTO).unwrap();

    let plaintext_first_line = pass_context
        .decrypt_file(&firefox_credentials.path)
        .unwrap()
        .first_line()
        .unwrap();

    let email = firefox_credentials.name.rsplit_once('/').unwrap().1;
    let password = plaintext_first_line.unsecure_to_str().unwrap();

    // TODO: move this crypto stuff somewhere else
    let email_salt = kwe("quickStretch", email);
    let mut quick_stretched_pw = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        email_salt.as_bytes(),
        1000,
        &mut quick_stretched_pw,
    );
    let mut auth_pw = [0u8; 32];
    let quick_stretched_pw_hdkf = Hkdf::<Sha256>::new(None, &quick_stretched_pw);
    quick_stretched_pw_hdkf
        .expand(kw("authPW").as_bytes(), &mut auth_pw)
        .unwrap();

    let mut unwrap_b_key = [0u8; 32];
    quick_stretched_pw_hdkf
        .expand(kw("unwrapBkey").as_bytes(), &mut unwrap_b_key)
        .unwrap();

    let auth_pwd_hex = hex::encode(auth_pw);

    let account_login_response = match client.account_login(email, &auth_pwd_hex, None).await {
        Ok(account_login_response) => account_login_response,
        Err(bad_request_error) => {
            match bad_request_error.errno {
                125 => {
                    assert!(bad_request_error.verification_method.is_some());
                    client.account_login_send_unblock_code(email).await;
                    print!("A verification code sent to {}: ", email);
                    io::stdout().flush().unwrap();
                    let mut unblock_code = String::new();
                    std::io::stdin().read_line(&mut unblock_code).unwrap();
                    client
                        .account_login(
                            email,
                            &auth_pwd_hex,
                            Some(Verification::EmailCaptcha(unblock_code.trim())),
                        )
                        // TODO move error handling into the api code instead.
                        .await
                        .unwrap_or_else(|bad_request_error| match bad_request_error.errno {
                            127 => {
                                println!("{}", bad_request_error.message);
                                panic!();
                            }
                            _ => unimplemented!(),
                        })
                }
                127 => {
                    // Cannot have "Invalid unblock code" when no unblock code is given
                    unreachable!();
                }
                _ => unimplemented!(),
            }
        }
    };
    let mut derived_key_fetch_token = [0u8; 96];
    Hkdf::<Sha256>::new(
        None,
        &hex::decode(account_login_response.key_fetch_token).unwrap(),
    )
    .expand(kw("keyFetchToken").as_bytes(), &mut derived_key_fetch_token)
    .unwrap();

    let token_id = &derived_key_fetch_token[0..32];
    let req_hmac_key = &derived_key_fetch_token[32..64];
    let key_request_key = &derived_key_fetch_token[64..96];

    dbg!(key_request_key, token_id, req_hmac_key, key_request_key);

    let hawk_credentials = hawk::Credentials {
        id: hex::encode(token_id),
        key: hawk::Key::new(req_hmac_key, hawk::DigestAlgorithm::Sha256).unwrap(),
    };

    let bundle = hex::decode(client.account_keys(&hawk_credentials).await.bundle).unwrap();
    let ciphertext = &bundle[0..64];
    let mac = &bundle[64..96];

    let mut derived_from_key_request_key = [0u8; 96];
    Hkdf::<Sha256>::new(None, key_request_key)
        .expand(
            kw("account/keys").as_bytes(),
            &mut derived_from_key_request_key,
        )
        .unwrap();

    let mut mac_verifer =
        Hmac::<Sha256>::new_from_slice(&derived_from_key_request_key[0..32]).unwrap();
    mac_verifer.update(ciphertext);
    mac_verifer
        .verify(mac)
        .expect("!!! CRYPTOGRAPHY ERROR SPOOFING IS BEING ATTEMPTED !!!");

    xor(&mut derived_from_key_request_key[32..96], ciphertext);
    xor(&mut derived_from_key_request_key[64..96], &unwrap_b_key);

    let key_b = &derived_from_key_request_key[64..96];

    let fxa_client_state = hex::encode(&Sha256::new().chain(&key_b).finalize()[0..16]);
    // TODO: this can be done concurrently
    let browserid_assertion =
        crypto::get_browserid_assertion(client, &account_login_response.session_token).await;

    let sync_server = client
        .sync_server_tokens(&fxa_client_state, &browserid_assertion)
        .await;
    let sync_server_credentials = hawk::Credentials {
        id: sync_server.id,
        key: hawk::Key::new(sync_server.key.as_bytes(), hawk::DigestAlgorithm::Sha256).unwrap(),
    };

    let mut sync_key_bundle = [0u8; 64];
    Hkdf::<Sha256>::new(None, key_b)
        .expand(kw("oldsync").as_bytes(), &mut sync_key_bundle)
        .unwrap();

    let crypto_keys_object = client
        .get_storage_object(
            &sync_server.api_endpoint,
            "crypto/keys",
            &sync_server_credentials,
        )
        .await;
    let payload = crypto_keys_object.get_payload();

    let plaintext: CryptoKeyRecord =
        serde_json::from_slice(&payload.decrypt(&sync_key_bundle[0..32], &sync_key_bundle[32..64]))
            .unwrap();

    let key = base64::decode(&plaintext.default[0]).unwrap();
    let hmac_key = base64::decode(&plaintext.default[1]).unwrap();

    let online_passwords = client
        .get_passwords(
            &sync_server.api_endpoint,
            &sync_server_credentials,
            &key,
            &hmac_key,
        )
        .await;

    dbg!(online_passwords);

    for secret in store.secret_iter() {
        dbg!(secret);
    }
}

#[tokio::main]
async fn main() {
    let client = Client::new();

    let store = match std::env::var("PASSWORD_STORE_DIR") {
        Ok(store_dir) => Store::open(store_dir),
        Err(VarError::NotPresent) => Store::open(prs_lib::STORE_DEFAULT_ROOT),
        Err(VarError::NotUnicode(path)) => panic!("`{:?}` is not unicode.", path),
    }
    .unwrap();

    login(&client, &store).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_json_password_test() {
        let json = "{\"id\":\"{7f3db3a7-ef2d-0446-aad0-049f1b0ff0fa}\",\"hostname\":\"https://www.reddit.com\",\"formSubmitURL\":\"\",\"httpRealm\":null,\"username\":\"asdf\",\"password\":\"asdf\",\"usernameField\":\"\",\"passwordField\":\"\",\"timeCreated\":1626895557678,\"timePasswordChanged\":1626895557678}";
        serde_json::from_str::<api::Password>(json).unwrap();
    }
}
