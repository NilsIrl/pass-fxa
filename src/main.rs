use log::debug;
use prs_lib::{crypto::IsContext, Plaintext, Secret, Store};
use std::{convert::TryFrom, env::VarError, path::Path, process::exit};
use structopt::StructOpt;
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

#[derive(Clone)]
struct LocalLogin {
    password: Plaintext,
    username: String,
    url: Url,
    filter: Option<Filter>,
}

impl LocalLogin {
    fn new(prs_lib_plaintext: &Secret, context: &mut prs_lib::crypto::Context) -> Self {
        let plaintext = context
            .decrypt_file(&prs_lib_plaintext.path)
            .expect("Failed to decrypt password file");

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
            Filter::try_from(fxa_setting_plaintext.unsecure_to_str().unwrap())
                .expect("Unkown setting")
        });
        LocalLogin {
            password,
            username,
            url,
            filter,
        }
    }

    fn to_login(self, online_logins: &Vec<Login>) -> Option<Login> {
        for online_login in online_logins {
            if online_login.username == self.username && online_login.hostname == self.url {
                if online_login.password.unsecure() == self.password.unsecure_to_str().unwrap() {
                    // If the password is the same, leave unchanged
                    return None;
                } else {
                    // If the password is different, just change that
                    return Some(
                        online_login.with_password(self.password.unsecure_to_str().unwrap()),
                    );
                }
            }
        }
        // Create new login if not in remote_logins
        Some(Login::new(
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

#[derive(StructOpt)]
struct Opt {
    #[structopt(name = "pass-name")]
    fxa_creds_name: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();

    let opt = Opt::from_args();

    let mut firefox_credentials = None;

    // List of ambiguous matches
    let mut firefox_matches = Vec::new();

    let mut pass_context = prs_lib::crypto::context(prs_lib::crypto::PROTO).unwrap();
    let store = get_store();

    let mut local_logins = Vec::new();
    let mut include = false;
    let mut exclude = false;
    for secret in store.secret_iter() {
        let local_login = LocalLogin::new(&secret, &mut pass_context);
        if let Some(filter) = &local_login.filter {
            match filter {
                Filter::Include => include = true,
                Filter::Exclude => exclude = true,
            }
        }
        let mut current_is_cred = false;
        if local_login.url.host_str().unwrap() == "firefox.com" {
            current_is_cred = true;
            firefox_credentials = Some(local_login.clone());
            firefox_matches.push((secret.name, local_login.username.clone()));
        } else if let Some(ref fxa_creds_name) = opt.fxa_creds_name {
            if *fxa_creds_name == secret.name {
                current_is_cred = true;
                firefox_credentials = Some(local_login.clone());
            }
        }
        if current_is_cred {
            if let Some(Filter::Include) = local_login.filter {
            } else {
                // The filter value is not include, so don't add it to local_logins by continuing
                // the loop
                continue;
            }
        }
        local_logins.push(local_login);
    }

    match opt.fxa_creds_name {
        Some(_) => {
            if firefox_credentials.is_none() {
                panic!("Could not find Firefox Account credentials.");
            }
        }
        None => {
            match firefox_matches.len() {
                0 => panic!("Could not find Firefox Account credentials."),
                // Just use the value already in firefox_credentials
                1 => (),
                // TODO implement --username to be able to select which to use
                _ => {
                    eprintln!(
                    "Ambiguous Firefox Account credential locations, please specify the location of the credentials:");
                    for firefox_match in firefox_matches {
                        eprintln!("- {}: {}", firefox_match.0, firefox_match.1);
                    }
                    exit(1);
                }
            }
        }
    }

    if exclude && include {
        println!("Ambiguous settings, include & exclude both present.");
        return;
    }

    let firefox_credentials = firefox_credentials.unwrap();

    let sync_client = SyncClient::new(
        &firefox_credentials.username,
        firefox_credentials.password.unsecure_to_str().unwrap(),
    )
    .await;

    let remote_logins = sync_client.get_logins().await;

    debug!("{:?}", remote_logins);

    let logins_to_upload: Vec<_> = if exclude || include {
        local_logins
            .into_iter()
            .filter(|login| include == login.filter.is_some())
            .filter_map(|local_login| local_login.to_login(&remote_logins))
            .collect()
    } else {
        local_logins
            .into_iter()
            .filter_map(|local_login| local_login.to_login(&remote_logins))
            .collect()
    };

    println!("Uploading {} passwords.", logins_to_upload.len());
    debug!("Passwords to upload: {:?}", logins_to_upload);
    sync_client.put_logins(&logins_to_upload).await;
}
