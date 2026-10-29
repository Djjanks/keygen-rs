//! Local live check, not part of the PR: how distribution APIs behave for a
//! suspended and an expired license. Temporarily changes the test license with
//! the admin token and restores it at the end.
//! Needs commit "fix(client): do not follow redirects automatically" or later.
//!
//! cargo run --example live_license_status --all-features

use chrono::{Duration, Utc};
use keygen_rs::{
    config::{self, KeygenConfig},
    errors::Error,
    keygen_client::KeygenClient,
    license::{LicenseUpdateRequest, UpdateField},
    release::Release,
};
use std::env;

fn license_config() -> KeygenConfig {
    KeygenConfig {
        api_url: env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string()),
        account: env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"),
        product: env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set"),
        license_key: Some(env::var("KEYGEN_LICENSE_KEY").expect("KEYGEN_LICENSE_KEY must be set")),
        public_key: env::var("KEYGEN_PUBLIC_KEY").ok(),
        ..KeygenConfig::default()
    }
}

/// Prints what each distribution API returns for the license in its current state.
async fn probe(client: &KeygenClient, release: &Release, artifact: &str) {
    match client.upgrade_from("1.0.0", None).await {
        Ok(r) => println!(
            "     upgrade_from(1.0.0)   -> Ok({:?})",
            r.map(|r| r.version)
        ),
        Err(e) => println!(
            "     upgrade_from(1.0.0)   -> Err {:?}: {e}",
            e.api_error_kind()
        ),
    }
    match Release::list(None).await {
        Ok(r) => println!(
            "     Release::list         -> Ok({:?})",
            r.iter().map(|r| r.version.as_str()).collect::<Vec<_>>()
        ),
        Err(e) => println!(
            "     Release::list         -> Err {:?}: {e}",
            e.api_error_kind()
        ),
    }
    match release.download_artifact(artifact).await {
        Ok(_) => println!("     download_artifact     -> Ok(location)"),
        Err(e) => println!(
            "     download_artifact     -> Err {:?}: {e}",
            e.api_error_kind()
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    let license_key = env::var("KEYGEN_LICENSE_KEY").expect("KEYGEN_LICENSE_KEY must be set");
    let artifact = env::var("KEYGEN_ARTIFACT").expect("KEYGEN_ARTIFACT must be set");

    let admin = KeygenClient::builder()
        .api_url(env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string()))
        .account(env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"))
        .token(env::var("KEYGEN_ADMIN_TOKEN").expect("KEYGEN_ADMIN_TOKEN must be set"))
        .build()?;
    let user = KeygenClient::new(license_config())?;
    // `Release` methods use the global config: license key auth, as in a client app.
    config::set_config(license_config())?;

    let license = admin.licenses().get(&license_key).await?;
    println!(
        "License {}: status {:?}, expiry {:?}, suspended {:?}",
        license.id, license.status, license.expiry, license.suspended
    );
    let release = Release::list(None)
        .await?
        .into_iter()
        .find(|r| r.version == "1.1.0")
        .expect("release 1.1.0 must be published");

    println!("\nActive license:");
    probe(&user, &release, &artifact).await;

    println!("\nSuspended license:");
    match admin.licenses().suspend(&license.id).await {
        Ok(_) => probe(&user, &release, &artifact).await,
        Err(e) => println!("     suspend failed: {e}"),
    }
    let reinstated = admin.licenses().reinstate(&license.id).await;
    println!("     reinstate -> {:?}", reinstated.map(|l| l.status));

    println!("\nExpired license (expiry = now - 1 day):");
    let expire = LicenseUpdateRequest {
        expiry: UpdateField::Set(Utc::now() - Duration::days(1)),
        ..Default::default()
    };
    match admin.licenses().update(&license.id, expire).await {
        Ok(l) => {
            println!("     status {:?}, expiry {:?}", l.status, l.expiry);
            probe(&user, &release, &artifact).await;
        }
        Err(e) => println!("     update failed: {e}"),
    }
    let restore = LicenseUpdateRequest {
        expiry: match license.expiry {
            Some(expiry) => UpdateField::Set(expiry),
            None => UpdateField::Clear,
        },
        ..Default::default()
    };
    let restored = admin.licenses().update(&license.id, restore).await;
    println!(
        "     restore expiry -> {:?}",
        restored.map(|l| (l.status, l.expiry))
    );

    println!("\nRestored license:");
    probe(&user, &release, &artifact).await;
    Ok(())
}
