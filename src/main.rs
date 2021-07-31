use prs_lib::{crypto::IsContext, Plaintext, Store};
use std::{convert::TryFrom, env::VarError, path::Path};
use url::Url;

mod api;

use api::{Login, SyncClient};

#[derive(Clone)]
enum Filter {
    Exclude,
    Include,
}

impl TryFrom<&str> for Filter {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "exclude" => Ok(Self::Exclude),
            "include" => Ok(Self::Include),
            _ => Err(()),
        }
    }
}

impl Filter {
    fn from_str(setting: &str) -> Self {
        match setting {
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone)]
struct LocalLogin {
    password: Plaintext,
    username: String,
    url: Url,
    filter: Option<Filter>,
}

impl LocalLogin {
    fn new(prs_lib_plaintext: prs_lib::Secret, context: &mut prs_lib::crypto::Context) -> Self {
        let plaintext = context.decrypt_file(&prs_lib_plaintext.path).unwrap();

        // TODO: what to do if no password
        let password = plaintext.first_line().unwrap();

        // This is fine to perform as it costs nothing to create a Path
        let name = Path::new(&prs_lib_plaintext.name);
        let url = plaintext.property("url").map_or_else(
            |_| {
                Url::parse(&format!(
                    "https://{}",
                    name.parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                ))
                .unwrap()
            },
            |url_plaintext| Url::parse(url_plaintext.unsecure_to_str().unwrap()).unwrap(),
        );

        let username = match plaintext.property("login") {
            Ok(login_plaintext) => login_plaintext.unsecure_to_str().unwrap().to_string(),
            Err(_) => name.file_name().unwrap().to_str().unwrap().to_string(),
        };
        let filter = plaintext.property("fxa").ok().map(|fxa_setting_plaintext| {
            Filter::from_str(fxa_setting_plaintext.unsecure_to_str().unwrap())
        });
        LocalLogin {
            password,
            username,
            url,
            filter,
        }
    }

    fn to_login(self, online_logins: &Vec<Login>) -> Login {
        online_logins
            .iter()
            .find_map(|login| {
                if login.username == self.username && login.hostname == self.url {
                    Some(login.with_password(self.password.unsecure_to_str().unwrap()))
                } else {
                    None
                }
            })
            .unwrap_or(Login::new(
                &self.username,
                self.password.unsecure_to_str().unwrap(),
                self.url,
            ))
    }
}

fn get_store() -> Store {
    match std::env::var("PASSWORD_STORE_DIR") {
        Ok(store_dir) => Store::open(store_dir),
        Err(VarError::NotPresent) => Store::open(prs_lib::STORE_DEFAULT_ROOT),
        Err(VarError::NotUnicode(path)) => panic!("`{:?}` is not unicode.", path),
    }
    .unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let firefox_credentials;
    let mut pass_context = prs_lib::crypto::context(prs_lib::crypto::PROTO).unwrap();

    let mut firefox_matches = Vec::new();
    let mut local_logins = Vec::new();
    let mut include = false;
    let mut exclude = false;
    for secret in get_store().secret_iter() {
        let local_login = LocalLogin::new(secret, &mut pass_context);
        if let Some(filter) = &local_login.filter {
            match filter {
                Filter::Include => include = true,
                Filter::Exclude => exclude = false,
            }
        }
        if local_login.url.host_str().unwrap() == "firefox.com" {
            firefox_matches.push(local_login.clone());
            if let Some(Filter::Include) = local_login.filter {}
            {
                continue;
            }
        } else {
            local_logins.push(local_login);
        }
    }

    match firefox_matches.len() {
        0 => panic!("Could not find Firefox Account credentials."),
        1 => {
            firefox_credentials = &firefox_matches[0];
        }
        // TODO implement --username to be able to select which to use
        _ => panic!(
            "Ambiguous Firefox Account credential locations: {:?}",
            firefox_matches
                .iter()
                .map(|firefox_match| &firefox_match.username)
                .collect::<Vec<_>>()
        ),
    }

    if exclude && include {
        println!("Ambiguous settings, include & exclude both present.");
        return;
    }

    let sync_client = SyncClient::new(
        &firefox_credentials.username,
        firefox_credentials.password.unsecure_to_str().unwrap(),
    )
    .await;

    let remote_logins = sync_client.get_logins().await;

    dbg!(&remote_logins);

    let logins_to_upload: Vec<_> = if exclude || include {
        local_logins
            .into_iter()
            .filter(|login| include == login.filter.is_some())
            .map(|local_login| local_login.to_login(&remote_logins))
            .collect()
    } else {
        local_logins
            .into_iter()
            .map(|local_login| local_login.to_login(&remote_logins))
            .collect()
    };

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
