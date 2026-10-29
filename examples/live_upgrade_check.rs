//! Local live check, not part of the PR: upgrade check by current version.
//! Needs commit "feat(release): check for upgrade by current version" or later.
//!
//! cargo run --example live_upgrade_check --no-default-features --features rustls,license-key

use keygen_rs::{
    config::{self, KeygenConfig},
    errors::Error,
    keygen_client::KeygenClient,
    release::{Release, ReleaseChannel, ReleaseUpgradeRequest},
};
use std::env;

fn report<T>(failures: &mut u32, name: &str, result: Result<T, String>) -> Option<T> {
    match result {
        Ok(value) => {
            println!("PASS {name}");
            Some(value)
        }
        Err(err) => {
            println!("FAIL {name}: {err}");
            *failures += 1;
            None
        }
    }
}

fn config(product: &str, license_key: &str) -> KeygenConfig {
    KeygenConfig {
        api_url: env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string()),
        account: env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"),
        product: product.to_string(),
        license_key: Some(license_key.to_string()),
        public_key: env::var("KEYGEN_PUBLIC_KEY").ok(),
        ..KeygenConfig::default()
    }
}

/// Expect `upgrade_from` to return the given version (`None` = no upgrade).
fn expect_version(
    result: Result<Option<Release>, Error>,
    expected: Option<&str>,
) -> Result<(), String> {
    let got = result.map_err(|e| format!("error: {e}"))?;
    let got = got.as_ref().map(|r| r.version.as_str());
    println!("     -> {got:?}");
    (got == expected)
        .then_some(())
        .ok_or(format!("expected {expected:?}"))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    let product = env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set");
    let license_key = env::var("KEYGEN_LICENSE_KEY").expect("KEYGEN_LICENSE_KEY must be set");
    config::set_config(config(&product, &license_key))?;
    let mut failures = 0;

    report(
        &mut failures,
        "1.0.0 -> Some(1.1.0)",
        expect_version(Release::upgrade_from("1.0.0", None).await, Some("1.1.0")),
    );
    report(
        &mut failures,
        "1.1.0 (latest) -> None",
        expect_version(Release::upgrade_from("1.1.0", None).await, None),
    );
    report(
        &mut failures,
        "2.0.0 (newer than any release) -> None",
        expect_version(Release::upgrade_from("2.0.0", None).await, None),
    );

    // Not asserted: shows how Keygen treats versions that are not releases.
    for version in ["0.9.0", "not-a-version"] {
        match Release::upgrade_from(version, None).await {
            Ok(r) => println!("INFO {version} -> {:?}", r.map(|r| r.version)),
            Err(e) => println!("INFO {version} -> error: {e}"),
        }
    }

    let beta = ReleaseUpgradeRequest {
        channel: Some(ReleaseChannel::Beta),
        ..Default::default()
    };
    report(
        &mut failures,
        "channel beta includes stable releases -> Some(1.1.0)",
        expect_version(
            Release::upgrade_from("1.0.0", Some(&beta)).await,
            Some("1.1.0"),
        ),
    );

    let other_product = ReleaseUpgradeRequest {
        product: Some("00000000-0000-0000-0000-000000000000".to_string()),
        ..Default::default()
    };
    report(
        &mut failures,
        "unknown product in request -> None (documented limitation)",
        expect_version(
            Release::upgrade_from("1.0.0", Some(&other_product)).await,
            None,
        ),
    );

    let client = KeygenClient::new(config(&product, &license_key))?;
    report(
        &mut failures,
        "KeygenClient::upgrade_from 1.0.0 -> Some(1.1.0)",
        expect_version(client.upgrade_from("1.0.0", None).await, Some("1.1.0")),
    );

    let no_product = KeygenClient::new(config("", &license_key))?;
    match no_product.upgrade_from("1.0.0", None).await {
        Ok(r) => println!(
            "INFO without product in config -> {:?}",
            r.map(|r| r.version)
        ),
        Err(e) => println!("INFO without product in config -> error: {e}"),
    }

    let invalid = KeygenClient::new(config(&product, "INVALID-LICENSE-KEY"))?;
    report(
        &mut failures,
        "invalid license key -> Err, not None",
        match invalid.upgrade_from("1.0.0", None).await {
            Ok(r) => Err(format!("got Ok({:?})", r.map(|r| r.version))),
            Err(e) => {
                println!("     {e} ({:?})", e.api_error_kind());
                Ok(())
            }
        },
    );

    report(
        &mut failures,
        "instance Release::upgrade still works",
        async {
            let current = Release::list(None)
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|r| r.version == "1.0.0")
                .ok_or("release 1.0.0 not found")?;
            let next = current.upgrade(None).await.map_err(|e| e.to_string())?;
            println!("     -> {}", next.version);
            (next.version == "1.1.0")
                .then_some(())
                .ok_or("expected 1.1.0".to_string())
        }
        .await,
    );

    println!("\n{failures} failure(s)");
    Ok(())
}
