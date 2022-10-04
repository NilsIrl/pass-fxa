use pass_fxa_lib::SyncClient;
use std::env::var;

#[tokio::main]
async fn main() {
    let email = var("HELPER_EMAIL").unwrap();
    let password = var("HELPER_PASSWORD").unwrap();
    let f = SyncClient::new(&email, &password).await;
    let logins = f.get_logins().await;
    for login in logins {
        println!("{:?}", login);
    }
}
