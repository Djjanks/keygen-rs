//! Local helper, not part of the PR: creates the resources needed to test the
//! release flow against a real Keygen account and prints the `.env` values.
//!
//! Every run creates a new product, so runs do not interfere with each other:
//! - product with LICENSED distribution (releases are visible to its licenses only);
//! - policy with LICENSE authentication (the license key can call the API);
//! - license for that policy;
//! - release 1.0.0, published, without artifacts (the "current" version);
//! - release 1.1.0, draft: upload a signed artifact with the Keygen CLI and publish it.
//!
//! cargo run --example setup_test_env --all-features

#[path = "common/mod.rs"]
mod common;

use keygen_rs::{
    errors::Error,
    license::{License, LicenseCreateRequest},
    policy::{AuthenticationStrategy, CreatePolicyRequest, Policy},
    product::{CreateProductRequest, DistributionStrategy, Product},
    release::{CreateReleaseRequest, Release, ReleaseChannel, ReleaseStatus},
};
use std::env;

const CURRENT_VERSION: &str = "1.0.0";
const UPGRADE_VERSION: &str = "1.1.0";

#[tokio::main]
async fn main() -> Result<(), Error> {
    common::load_env();
    common::configure_admin()?;
    check_account_public_key();

    let suffix = common::unique_suffix();

    let product = Product::create(CreateProductRequest {
        name: format!("keygen-rs test {suffix}"),
        code: Some(format!("keygen-rs-test-{suffix}")),
        distribution_strategy: Some(DistributionStrategy::Licensed),
        url: None,
        platforms: None,
        permissions: None,
        metadata: None,
    })
    .await?;
    println!("Created product {} ({})", product.name, product.id);

    let policy = Policy::create(CreatePolicyRequest {
        name: format!("keygen-rs test {suffix}"),
        authentication_strategy: Some(AuthenticationStrategy::License),
        product_id: product.id.clone(),
        ..Default::default()
    })
    .await?;
    println!("Created policy {} ({})", policy.name, policy.id);

    let license = License::create(LicenseCreateRequest {
        policy_id: policy.id.clone(),
        name: Some(format!("keygen-rs test {suffix}")),
        ..Default::default()
    })
    .await?;
    println!("Created license {}", license.id);

    let current = create_release(&product.id, CURRENT_VERSION)
        .await?
        .publish()
        .await?;
    println!(
        "Created release {} ({}, {:?})",
        current.version, current.id, current.status
    );

    let upgrade = create_release(&product.id, UPGRADE_VERSION).await?;
    println!(
        "Created release {} ({}, {:?})",
        upgrade.version, upgrade.id, upgrade.status
    );

    let account = common::required_env("KEYGEN_ACCOUNT");
    println!();
    println!("# .env");
    println!("KEYGEN_PRODUCT={}", product.id);
    println!("KEYGEN_LICENSE_KEY={}", license.key);
    println!("KEYGEN_CURRENT_VERSION={CURRENT_VERSION}");
    println!("KEYGEN_ARTIFACT=<filename you upload below>");
    println!("KEYGEN_SIGNING_PUBLIC_KEY=<contents of keygen.pub>");
    println!();
    println!("# Signed artifact for {UPGRADE_VERSION} (Keygen CLI, PowerShell):");
    println!("keygen genkey   # once: writes keygen.key and keygen.pub");
    println!(
        "keygen upload <path> --account {account} --product {} --token $env:KEYGEN_ADMIN_TOKEN \
         --release {UPGRADE_VERSION} --signing-key keygen.key",
        product.id
    );
    println!(
        "keygen publish --account {account} --product {} --token $env:KEYGEN_ADMIN_TOKEN \
         --release {UPGRADE_VERSION}",
        product.id
    );

    Ok(())
}

async fn create_release(product_id: &str, version: &str) -> Result<Release, Error> {
    Release::create(CreateReleaseRequest {
        version: version.to_string(),
        channel: ReleaseChannel::Stable,
        product_id: product_id.to_string(),
        name: Some(format!("v{version}")),
        description: None,
        status: Some(ReleaseStatus::Draft),
        tag: None,
        metadata: None,
    })
    .await
}

/// The SDK verifies response signatures with the account Ed25519 key: 64 hex chars.
fn check_account_public_key() {
    match env::var("KEYGEN_PUBLIC_KEY") {
        Ok(key) if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) => {}
        Ok(key) => println!(
            "Warning: KEYGEN_PUBLIC_KEY is {} chars, expected the 64-char hex Ed25519 \
             account key (Settings in the dashboard)",
            key.len()
        ),
        Err(_) => println!("Warning: KEYGEN_PUBLIC_KEY is not set"),
    }
}
