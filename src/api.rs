use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use futures::{stream::FuturesUnordered, StreamExt};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::{rngs::OsRng, RngCore};
use reqwest::{header, Request, StatusCode};
use rsa::{hash::Hash, padding::PaddingScheme, PublicKeyParts, RSAPrivateKey};
use secstr::SecUtf8;
use serde::{de, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use tokio::time::{sleep, Duration};
use url::Url;

const DURATION: u64 = 60;

#[derive(Deserialize)]
struct CryptoKeyRecord {
    default: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    id: String,
    pub hostname: Url,
    #[serde(rename = "formSubmitURL")]
    form_submit_url: String,
    http_realm: Option<String>,
    pub username: String,
    pub password: SecUtf8,
    username_field: String,
    password_field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_last_used: Option<u64>,
    // TODO: update this
    #[serde(skip_serializing_if = "Option::is_none")]
    time_created: Option<u64>,
    // TODO: update this
    #[serde(skip_serializing_if = "Option::is_none")]
    time_password_changed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_used: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum PasswordBSORecord {
    Password(Login),
    Deleted { id: String, deleted: bool },
}

fn generate_bso_id() -> String {
    let bytes: [u8; 9] = rand::random();
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

impl Login {
    pub fn new(username: &str, password: &str, hostname: Url) -> Self {
        Self {
            id: generate_bso_id(),
            hostname,
            form_submit_url: String::new(),
            http_realm: None,
            username: username.to_string(),
            password: password.into(),
            username_field: String::new(),
            password_field: String::new(),
            time_created: None,
            time_last_used: None,
            time_password_changed: None,
            time_used: None,
        }
    }

    pub fn with_password(&self, new_password: &str) -> Self {
        Self {
            password: new_password.into(),
            ..self.clone()
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountLoginRequest<'a, 'b, 'c> {
    email: &'a str,
    #[serde(rename = "authPW")]
    auth_pw: &'a str,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    unblock_code: Option<&'b str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_method: Option<&'c str>,
}

#[derive(Deserialize)]
pub struct SyncServerToken {
    pub id: String,
    pub key: String,
    uid: u64,
    pub api_endpoint: String,
    duration: u32,
    hashalg: String,
    hashed_fxa_uid: String,
    node_type: String,
}

#[derive(Deserialize, Serialize)]
pub struct Payload {
    pub ciphertext: String,
    #[serde(rename = "IV")]
    pub iv: String,
    pub hmac: String,
}

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
#[derive(Deserialize, Serialize)]
pub struct BSO {
    id: String,
    //modified: f64,
    #[serde(with = "serde_with::json::nested")]
    payload: Payload,
}

impl BSO {
    fn from_object(object: &Login, key: &[u8], hmac_key: &[u8]) -> Self {
        let iv = generate_iv();
        let cipher = Aes256Cbc::new_from_slices(key, &iv).unwrap();
        let mut payload = serde_json::to_vec(&object).unwrap();
        let plaintext_len = payload.len();
        payload.extend_from_slice(&[0u8; 16][0..16 - plaintext_len % 16]);
        cipher.encrypt(&mut payload, plaintext_len).unwrap();
        let ciphertext_base64 = base64::encode(payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
        mac.update(ciphertext_base64.as_bytes());
        //cipher.encrypt(buffer, pos)
        BSO {
            id: object.id.to_string(),
            payload: Payload {
                iv: base64::encode(iv),
                ciphertext: ciphertext_base64,
                hmac: hex::encode(mac.finalize().into_bytes()),
            },
        }
    }

    fn decrypt_payload(&self, key: &[u8], hmac_key: &[u8]) -> Vec<u8> {
        let payload = &self.payload;

        let cipher =
            Aes256Cbc::new_from_slices(key, &base64::decode(&payload.iv).unwrap()).unwrap();
        let mut ciphertext = base64::decode(&payload.ciphertext).unwrap();
        let len = cipher.decrypt(&mut ciphertext).unwrap().len();

        let mut mac_verifier = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
        mac_verifier.update(payload.ciphertext.as_bytes());
        mac_verifier
            .verify(&hex::decode(&payload.hmac).unwrap())
            .unwrap();

        ciphertext.truncate(len);
        ciphertext
    }
}

impl<'a, 'b, 'c> AccountLoginRequest<'a, 'b, 'c> {
    fn new(email: &'a str, auth_pw: &'a str, verification: Option<Verification<'b>>) -> Self {
        let verification_method = verification
            .as_ref()
            .map(|verification| match verification {
                Verification::EmailCaptcha(_) => "email-captcha",
            });
        let unblock_code = verification.map(|verification| match verification {
            Verification::EmailCaptcha(code) => code,
        });

        Self {
            email,
            auth_pw,
            unblock_code,
            verification_method,
            // Reason is required so it doesn't ask for an unblock code
            reason: "login",
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccountLoginResponse {
    uid: String,
    pub session_token: String,
    pub key_fetch_token: String,
    verification_method: Option<String>,
    verified: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BadRequestError {
    code: u16,
    pub errno: u16,
    pub message: String,
    pub verification_method: Option<String>,
    verification_reason: Option<String>,
}

#[derive(Serialize)]
struct SendUnblockCodeRequest<'a> {
    email: &'a str,
}

#[derive(Serialize)]
pub struct PublicKey<'a> {
    algorithm: &'a str,
    n: &'a str,
    e: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateSignRequest<'a> {
    public_key: PublicKey<'a>,
    duration: u64,
}

#[derive(Deserialize)]
pub struct CertificateSignResponse {
    pub cert: String,
}

#[derive(Deserialize)]
pub struct AccountKeysResponse {
    pub bundle: String,
}

pub struct SyncClient {
    http_client: reqwest::Client,
    api_endpoint: String,
    sync_server_credentials: hawk::Credentials,
    key_bundle: [u8; 64],
}

pub struct FxaClient {
    client: reqwest::Client,
    base_uri: String,
}

pub enum Verification<'a> {
    EmailCaptcha(&'a str),
}

fn hawk_authenticate(request: &mut Request, credentials: &hawk::Credentials) {
    let method = request.method().clone();
    let url = request.url().clone();
    let mut hawk_request_builder = hawk::RequestBuilder::from_url(method.as_str(), &url).unwrap();
    let payload_hash;
    if let Some(body) = request.body() {
        payload_hash = hawk::PayloadHasher::hash(
            request.headers().get("Content-Type").unwrap().as_bytes(),
            hawk::SHA256,
            body.as_bytes().unwrap(),
        )
        .unwrap();
        hawk_request_builder = hawk_request_builder.hash(&payload_hash[..]);
    }

    let hawk_request = hawk_request_builder.request();
    assert!(request
        .headers_mut()
        .insert(
            header::AUTHORIZATION,
            format!("Hawk {}", hawk_request.make_header(credentials).unwrap())
                .parse()
                .unwrap(),
        )
        .is_none());
}

impl FxaClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("reqwest (pass-fxa)")
                //.proxy(reqwest::Proxy::all("http://localhost:8080").unwrap())
                //.danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            // TODO: allow user to choose FxA server
            base_uri: "https://api.accounts.firefox.com/v1".to_string(),
        }
    }

    // TODO: move this crypto stuff somewhere else
    pub async fn get_sync_client(self, email: &str, password: &str) -> SyncClient {
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

        let account_login_response = match self.account_login(email, &auth_pwd_hex, None).await {
            Ok(account_login_response) => account_login_response,
            Err(bad_request_error) => {
                match bad_request_error.errno {
                    125 => {
                        assert!(bad_request_error.verification_method.is_some());
                        self.account_login_send_unblock_code(email).await;
                        print!("A verification code sent to {}: ", email);
                        io::stdout().flush().unwrap();
                        let mut unblock_code = String::new();
                        std::io::stdin().read_line(&mut unblock_code).unwrap();
                        self.account_login(
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

        if let Some(ref verification_method) = account_login_response.verification_method {
            match verification_method.as_str() {
                "email" => println!("Please confirm sign-in by email at {}", email),
                _ => unimplemented!(),
            }
        }

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

        let hawk_credentials = hawk::Credentials {
            id: hex::encode(token_id),
            key: hawk::Key::new(req_hmac_key, hawk::DigestAlgorithm::Sha256).unwrap(),
        };

        let bundle = hex::decode(loop {
            match self.account_keys(&hawk_credentials).await {
                Ok(account_keys) => break account_keys.bundle,
                Err(_) => {
                    if account_login_response.verification_method.is_none() {
                        unimplemented!()
                    } else {
                        sleep(Duration::from_millis(500)).await
                    }
                }
            }
        })
        .unwrap();
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
        // TODO: this can be done concurrently with the previous request
        let browserid_assertion = &self
            .get_browserid_assertion(&account_login_response.session_token)
            .await;

        let sync_server = self
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

        SyncClient::from_sync_key_bundle(
            self.client,
            sync_server.api_endpoint,
            sync_server_credentials,
            sync_key_bundle,
        )
        .await
    }

    pub async fn account_login(
        &self,
        email: &str,
        auth_pw: &str,
        verification: Option<Verification<'_>>,
    ) -> Result<AccountLoginResponse, BadRequestError> {
        let response = self
            .client
            .post(format!("{}/account/login?keys=true", self.base_uri))
            .json(&AccountLoginRequest::new(email, auth_pw, verification))
            .send()
            .await
            .unwrap();
        if response.status() == StatusCode::BAD_REQUEST {
            Err(response.json::<BadRequestError>().await.unwrap())
        } else {
            Ok(response.json::<AccountLoginResponse>().await.unwrap())
        }
    }

    pub async fn account_login_send_unblock_code(&self, email: &str) {
        let response = self
            .client
            .post(format!("{}/account/login/send_unblock_code", self.base_uri))
            .json(&SendUnblockCodeRequest { email })
            .send()
            .await
            .unwrap();
        match response.status() {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => {
                println!(
                    "Too many requests! Try again in {} seconds.",
                    std::str::from_utf8(response.headers().get("retry-after").unwrap().as_bytes())
                        .unwrap()
                );
                // TODO proper exit
                panic!("TODO proper ending of stuff");
            }
            _ => unimplemented!(),
        }
    }

    pub async fn account_keys(
        &self,
        credentials: &hawk::Credentials,
    ) -> Result<AccountKeysResponse, reqwest::Error> {
        let mut request = self
            .client
            .get(format!("{}/account/keys", self.base_uri))
            .build()
            .unwrap();
        hawk_authenticate(&mut request, credentials);
        self.client.execute(request).await.unwrap().json().await
    }

    pub async fn certificate_sign(
        &self,
        n: &str,
        e: &str,
        credentials: &hawk::Credentials,
    ) -> (CertificateSignResponse, u64) {
        let url = Url::parse(&format!("{}/certificate/sign", self.base_uri)).unwrap();
        let mut request = self
            .client
            .post(url.clone())
            .json(&CertificateSignRequest {
                public_key: PublicKey {
                    algorithm: "RS",
                    n,
                    e,
                },
                // Value in milliseconds
                duration: DURATION * 1000,
            })
            .build()
            .unwrap();
        hawk_authenticate(&mut request, credentials);
        let response = self.client.execute(request).await.unwrap();
        let server_time = response
            .headers()
            .get("timestamp")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();

        (response.json().await.unwrap(), server_time)
    }

    pub async fn sync_server_tokens(
        &self,
        client_state: &str,
        browserid_assertion: &str,
    ) -> SyncServerToken {
        self.client
            .get("https://token.services.mozilla.com/1.0/sync/1.5")
            .header(
                header::AUTHORIZATION,
                format!("BrowserID {}", browserid_assertion),
            )
            .header("X-Client-State", client_state)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    pub async fn _info_collections(
        &self,
        sync_server_endpoint: &str,
        credentials: &hawk::Credentials,
    ) {
        let mut request = self
            .client
            .get(format!("{}/info/collections", sync_server_endpoint))
            .build()
            .unwrap();
        hawk_authenticate(&mut request, credentials);
        self.client.execute(request).await.unwrap();
    }
    pub async fn get_browserid_assertion(&self, session_token: &str) -> String {
        let mut derived_from_session_token = [0u8; 64];
        println!("Generating RSA Private Key. This may take a while.");
        let rsa_private_key = RSAPrivateKey::new(&mut OsRng, 2048).unwrap();
        Hkdf::<Sha256>::new(None, &hex::decode(session_token).unwrap())
            .expand(
                kw("sessionToken").as_bytes(),
                &mut derived_from_session_token,
            )
            .unwrap();
        let (certificate, server_time) = self
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
                    exp: (server_time + DURATION) * 1000,
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
}

impl SyncClient {
    pub async fn get_storage_object<T>(&self, object: impl AsRef<str>) -> T
    where
        T: de::DeserializeOwned,
    {
        let mut request = self
            .http_client
            .get(format!("{}/storage/{}", self.api_endpoint, object.as_ref()))
            .build()
            .unwrap();
        hawk_authenticate(&mut request, &self.sync_server_credentials);
        let decrypted_payload = self
            .http_client
            .execute(request)
            .await
            .unwrap()
            .json::<BSO>()
            .await
            .unwrap()
            .decrypt_payload(&self.key_bundle[0..32], &self.key_bundle[32..64]);
        serde_json::from_slice(&decrypted_payload).unwrap()
    }
    pub async fn new(email: &str, password: &str) -> Self {
        FxaClient::new().get_sync_client(email, password).await
    }
    async fn from_sync_key_bundle(
        http_client: reqwest::Client,
        api_endpoint: String,
        sync_server_credentials: hawk::Credentials,
        sync_key_bundle: [u8; 64],
    ) -> Self {
        let sync = Self {
            http_client,
            api_endpoint,
            sync_server_credentials,
            key_bundle: sync_key_bundle,
        };

        let plaintext: CryptoKeyRecord = sync.get_storage_object("crypto/keys").await;
        let mut bulk_key_bundle = [0u8; 64];
        base64::decode_config_slice(
            &plaintext.default[0],
            base64::STANDARD,
            &mut bulk_key_bundle,
        )
        .unwrap();
        base64::decode_config_slice(
            &plaintext.default[1],
            base64::STANDARD,
            &mut bulk_key_bundle[32..64],
        )
        .unwrap();

        SyncClient {
            key_bundle: bulk_key_bundle,
            ..sync
        }
    }

    pub async fn get_collection(&self, collection: &str) -> Vec<String> {
        let mut request = self
            .http_client
            .get(format!("{}/storage/{}", self.api_endpoint, collection))
            .build()
            .unwrap();
        hawk_authenticate(&mut request, &self.sync_server_credentials);
        self.http_client
            .execute(request)
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    pub async fn get_logins(&self) -> Vec<Login> {
        let mut passwords = Vec::new();
        let password_bsos = self
            .get_collection("passwords")
            .await
            .iter()
            .map(|password_id| self.get_storage_object(format!("passwords/{}", password_id)))
            .collect::<FuturesUnordered<_>>();
        let passwords_len = password_bsos.len();
        let mut password_bsos_enumerate = password_bsos.enumerate();
        let mut stdout = io::stdout();
        print!("[0/{}] Downloading passwords", passwords_len);
        stdout.flush().unwrap();
        while let Some((i, password_bso)) = password_bsos_enumerate.next().await {
            if let PasswordBSORecord::Password(password) = password_bso {
                passwords.push(password);
            }
            print!("\r[{}/{}] Downloading passwords", i + 1, passwords_len);
            stdout.flush().unwrap();
        }
        println!();
        passwords
    }

    pub async fn put_logins(&self, logins: &Vec<Login>) {
        let mut request = self
            .http_client
            .post(format!("{}/storage/passwords", self.api_endpoint))
            .json(
                &logins
                    .iter()
                    .map(|login| {
                        BSO::from_object(login, &self.key_bundle[0..32], &self.key_bundle[32..64])
                    })
                    .collect::<Vec<_>>(),
            )
            .build()
            .unwrap();
        hawk_authenticate(&mut request, &self.sync_server_credentials);
        self.http_client.execute(request).await.unwrap();
    }
}

pub fn xor(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

pub fn kwe(name: &str, email: &str) -> String {
    format!("{}:{}", kw(name), email)
}

pub fn kw(name: &str) -> String {
    format!("identity.mozilla.com/picl/v1/{}", name)
}

#[derive(Serialize)]
struct Assertion<'a> {
    exp: u64,
    aud: &'a str,
}

pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    return iv;
}
#[cfg(test)]
mod tests {
    use super::*;

    // TODO: add test for only containing URL safe characters
    #[test]
    fn generate_bso_id_test1() {
        assert_eq!(12, generate_bso_id().len());
    }

    #[test]
    fn parse_bso() {
        serde_json::from_str::<BSO>(
            r#"
{
  "id": "ybhmIXr2Vj9Y",
  "modified": 1616761977.69,
  "payload": "{\"IV\":\"oZU7SOKC/bON6y7dpjl5OQ==\",\"hmac\":\"eebb747b790794d560b29897e9f1c4da9d3d2139bec9c64b526bd3cb0f096b46\",\"ciphertext\":\"V+qB+4Lb+6AeDmIKt/0GpnzWVC8eDrQJkzQfWhb1OsAHH4vqQaA2ZJVxuB8TmUA3xGVUxsUbIun9yc0B3ZM4KwaicqXdtWStlh+JEM9yJGAduDwwHZvPRINu1gEki5t6tw19Bira63RxyGyMj2lqpbGq0IIWOAKrKiPQFVteYLkjR9dRM+R6vJZB/5TC3eoMB75drHTNSB4UOxiUwmqmx6gZbXss+73Au+bs63ODx0A8wcDRyxThpQOKWVOhPvmSQLpWRzStNBI0z20owEg03QKevA6xheZ+vtOqnYcN7O0+5xBVTM3Xg2ykqVXrayeYnHig9KVRAucgH/ImBzenJw2/dTZeJKszLBuMxQ4vLSiDF8lSp6Pae7xLeDUdE+AbVCirOJX+Ren5XF17v9XhDV8C4Okn3gCbFKawu8cacvf5cna/Ezhsc1HuMu2HtgTA\"}",
  "sortindex": 1
}
            "#,
        ).unwrap();
    }

    #[test]
    fn deserialize_json_password_test() {
        let json = r#"
{
  "id": "{7f3db3a7-ef2d-0446-aad0-049f1b0ff0fa}",
  "hostname": "https://www.reddit.com",
  "formSubmitURL": "",
  "httpRealm": null,
  "username": "asdf",
  "password": "asdf",
  "usernameField": "",
  "passwordField": "",
  "timeCreated": 1626895557678,
  "timePasswordChanged": 1626895557678
}
        "#;
        serde_json::from_str::<PasswordBSORecord>(json).unwrap();
    }

    #[test]
    fn deserialize_nested() {
        #[derive(Deserialize)]
        struct B {
            c: String,
            d: u32,
        }

        #[derive(Deserialize)]
        struct Test {
            a: String,
            #[serde(with = "serde_with::json::nested")]
            b: B,
        }

        let object: Test = serde_json::from_str(
            r#"
            {
                "a": "string",
                "b": "{\"c\":\"c_string\",\"d\":1234}"
            }
        "#,
        )
        .unwrap();
    }
}
