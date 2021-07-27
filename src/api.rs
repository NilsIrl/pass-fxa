use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use futures::{stream::FuturesUnordered, StreamExt};
use hmac::{Hmac, Mac, NewMac};
use reqwest::{header, Request, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Password {
    #[serde(rename_all = "camelCase")]
    PasswordSite {
        id: String,
        hostname: String,
        #[serde(rename = "formSubmitURL")]
        form_submit_url: String,
        http_realm: Option<String>,
        username: String,
        password: String,
        username_field: String,
        password_field: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        time_last_used: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        time_created: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        time_password_changed: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        time_used: Option<u64>,
    },
    Deleted {
        id: String,
        deleted: bool,
    },
}

fn generate_bso_id() -> String {
    let bytes: [u8; 9] = rand::random();
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

impl Password {
    fn new(username: &str, password: &str, hostname: &str) -> Self {
        Self::PasswordSite {
            id: generate_bso_id(),
            hostname: hostname.to_string(),
            form_submit_url: String::new(),
            http_realm: None,
            username: username.to_string(),
            password: password.to_string(),
            username_field: String::new(),
            password_field: String::new(),
            time_created: None,
            time_last_used: None,
            time_password_changed: None,
            time_used: None,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountLoginRequest<'a, 'b, 'c> {
    email: &'a str,
    #[serde(rename = "authPW")]
    auth_pw: &'a str,
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

#[derive(Deserialize)]
pub struct BSO {
    id: String,
    modified: f64,
    // TODO: make this a payload
    payload: String,
}

impl BSO {
    // TODO use serde to do things properly
    pub fn get_payload(&self) -> Payload {
        serde_json::from_str(&self.payload).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Payload {
    pub ciphertext: String,
    #[serde(rename = "IV")]
    pub iv: String,
    pub hmac: String,
}

impl Payload {
    pub fn decrypt(&self, key: &[u8], hmac_key: &[u8]) -> Vec<u8> {
        type Aes256Cbc = Cbc<Aes256, Pkcs7>;

        let cipher = Aes256Cbc::new_from_slices(key, &base64::decode(&self.iv).unwrap()).unwrap();
        let mut ciphertext = base64::decode(&self.ciphertext).unwrap();
        let len = cipher.decrypt(&mut ciphertext).unwrap().len();

        let mut mac_verifier = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
        mac_verifier.update(self.ciphertext.as_bytes());
        mac_verifier
            .verify(&hex::decode(&self.hmac).unwrap())
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
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccountLoginResponse {
    uid: String,
    pub session_token: String,
    pub key_fetch_token: String,
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
    duration: u32,
}

#[derive(Deserialize)]
pub struct CertificateSignResponse {
    pub cert: String,
}

#[derive(Deserialize)]
pub struct AccountKeysResponse {
    pub bundle: String,
}

pub struct Client {
    client: reqwest::Client,
    base_uri: String,
}

pub enum Verification<'a> {
    EmailCaptcha(&'a str),
}

impl Client {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                // TODO the verfication email only include "reqwest", look into User Agent Spec
                .user_agent("pass-fxa (reqwest)")
                .proxy(reqwest::Proxy::all("http://localhost:8080").unwrap())
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            base_uri: "https://api.accounts.firefox.com/v1".to_string(),
        }
    }

    fn hawk_authenticate(request: &mut Request, credentials: &hawk::Credentials) {
        let method = request.method().clone();
        let url = request.url().clone();
        let mut hawk_request_builder =
            hawk::RequestBuilder::from_url(method.as_str(), &url).unwrap();
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

    pub async fn account_keys(&self, credentials: &hawk::Credentials) -> AccountKeysResponse {
        // TODO: use new instead of from_url, removes a dependency and is clearer
        // This requires the URL to be less hard coded
        let mut request = self
            .client
            .get(format!("{}/account/keys", self.base_uri))
            .build()
            .unwrap();
        Self::hawk_authenticate(&mut request, credentials);
        self.client
            .execute(request)
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    pub async fn certificate_sign(
        &self,
        n: &str,
        e: &str,
        credentials: &hawk::Credentials,
    ) -> CertificateSignResponse {
        let url = url::Url::parse(&format!("{}/certificate/sign", self.base_uri)).unwrap();
        let mut request = self
            .client
            .post(url.clone())
            .json(&CertificateSignRequest {
                public_key: PublicKey {
                    algorithm: "RS",
                    n,
                    e,
                },
                // The certificate is valid for 1 minute
                // TODO: remove "60 *" used for testing
                duration: 60 * 60 * 1000,
            })
            .build()
            .unwrap();
        Self::hawk_authenticate(&mut request, credentials);
        self.client
            .execute(request)
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    // TODO maybe return a storage server client?
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

    pub async fn info_collections(
        &self,
        sync_server_endpoint: &str,
        credentials: &hawk::Credentials,
    ) {
        let mut request = self
            .client
            .get(format!("{}/info/collections", sync_server_endpoint))
            .build()
            .unwrap();
        Self::hawk_authenticate(&mut request, credentials);
        self.client.execute(request).await.unwrap();
    }

    pub async fn get_storage_object(
        &self,
        sync_server_endpoint: &str,
        object: impl AsRef<str>,
        credentials: &hawk::Credentials,
    ) -> BSO {
        let mut request = self
            .client
            .get(format!(
                "{}/storage/{}",
                sync_server_endpoint,
                object.as_ref()
            ))
            .build()
            .unwrap();
        Self::hawk_authenticate(&mut request, credentials);
        self.client
            .execute(request)
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    pub async fn get_collection(
        &self,
        sync_server_endpoint: &str,
        collection: &str,
        credentials: &hawk::Credentials,
    ) -> Vec<String> {
        let mut request = self
            .client
            .get(format!("{}/storage/{}", sync_server_endpoint, collection))
            .build()
            .unwrap();
        Self::hawk_authenticate(&mut request, credentials);
        self.client
            .execute(request)
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    // TODO: This function can be relatively slow to run
    // It is now way faster tahnks to FuturesUnordered
    pub async fn get_passwords(
        &self,
        sync_server_endpoint: &str,
        credentials: &hawk::Credentials,
        key: &[u8],
        hmac_key: &[u8],
    ) -> Vec<Password> {
        let mut passwords = Vec::new();
        let mut password_bsos = self
            .get_collection(sync_server_endpoint, "passwords", credentials)
            .await
            .iter()
            .map(|password_id| {
                self.get_storage_object(
                    sync_server_endpoint,
                    format!("passwords/{}", password_id),
                    credentials,
                )
            })
            .collect::<FuturesUnordered<_>>();
        while let Some(password_bso) = password_bsos.next().await {
            passwords.push(
                serde_json::from_slice(&password_bso.get_payload().decrypt(key, hmac_key)).unwrap(),
            );
        }
        passwords
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: add test for only containing URL safe characters
    #[test]
    fn generate_bso_id_test1() {
        assert_eq!(12, generate_bso_id().len());
    }
}
