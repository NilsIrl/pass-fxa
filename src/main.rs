use prs_lib::{crypto::IsContext, Store};
use std::{env::VarError, path::Path};
use url::Url;

mod api;

use api::{Login, SyncClient};

fn get_store() -> Store {
    match std::env::var("PASSWORD_STORE_DIR") {
        Ok(store_dir) => Store::open(store_dir),
        Err(VarError::NotPresent) => Store::open(prs_lib::STORE_DEFAULT_ROOT),
        Err(VarError::NotUnicode(path)) => panic!("`{:?}` is not unicode.", path),
    }
    .unwrap()
}

#[tokio::main]
async fn main() {
    let store = get_store();

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

    let sync_client = SyncClient::new(email, password).await;

    let remote_logins: Vec<_> = sync_client.get_logins().await;

    let mut logins_to_upload = Vec::new();

    for secret in store.secret_iter() {
        let plaintext_first_line = pass_context
            .decrypt_file(&secret.path)
            .unwrap()
            .first_line()
            .unwrap();
        let store_password = plaintext_first_line.unsecure_to_str().unwrap();
        let path = Path::new(&secret.name);
        if let (Some(containing_folder), Some(store_username)) = (
            path.parent().and_then(|parent| {
                parent
                    .file_name()
                    .map(|containing_folder| containing_folder.to_str().unwrap())
            }),
            path.file_name()
                .map(|username_osstr| username_osstr.to_str().unwrap()),
        ) {
            match remote_logins.iter().find(|login| {
                (match Url::parse(&login.hostname) {
                    Ok(url) => url
                        .host_str()
                        .map(|host_str| host_str == containing_folder)
                        .unwrap_or(false),
                    Err(_) => false,
                } && store_username == login.username)
            }) {
                Some(matching_login) => {
                    if matching_login.password != store_password {
                        logins_to_upload.push(matching_login.with_password(store_password));
                    }
                }
                None => {
                    logins_to_upload.push(Login::new(
                        store_username,
                        store_password,
                        containing_folder,
                    ));
                }
            }
        }
    }

    println!("Uploading {} passwords.", logins_to_upload.len());
    sync_client.put_logins(&logins_to_upload).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_store_test() {
        let store = get_store();
        for secret in store.secret_iter() {
            let path = Path::new(&secret.name);
            if let Some(containing_folder) = path.parent().map(|parent| parent.file_name()) {
                dbg!(path.file_name(), containing_folder);
            }
        }
        panic!();
    }
}
