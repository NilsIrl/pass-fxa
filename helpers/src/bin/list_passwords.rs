use pass_fxa_lib::SyncClient;
use serde_json::Value;
use std::env::var;

#[tokio::main]
async fn main() {
    let email = var("HELPER_EMAIL").unwrap();
    let password = var("HELPER_PASSWORD").unwrap();
    let f = SyncClient::new(&email, &password).await;
    let logins = f.get_collection("passwords").await;
    for login in logins {
        let object: Value = f.get_storage_object(format!("passwords/{}", login)).await;
        println!("{}", object);
    }
}
