use pass_fxa_lib::SyncClient;
use std::env::var;

#[tokio::main]
async fn main() {
    let email = var("HELPER_EMAIL").unwrap();
    let password = var("HELPER_PASSWORD").unwrap();
    let f = SyncClient::new(&email, &password).await;
    //let logins = f.get_logins().await;
    let all_passwords = f.get_collection("passwords").await;
    f.delete_objects(
        &all_passwords
            .iter()
            .map(|password| password.as_str())
            .collect::<Vec<_>>(),
    )
    .await;
}
