//! Local live check, not part of the PR: read-only distribution APIs with
//! license key auth, built without the `token` feature.
//! Needs commit "feat(release): allow read-only distribution APIs with license key auth"
//! or later; `Artifact::get` passes only from "fix(client): do not follow redirects" on.
//!
//! cargo run --example live_license_key_reads --no-default-features --features rustls,license-key

use keygen_rs::{
    arch::Arch,
    artifact::Artifact,
    channel::Channel,
    config::{self, KeygenConfig},
    errors::Error,
    package::Package,
    platform::Platform,
    release::Release,
};
use std::env;

fn configure(license_key: String) -> Result<(), Error> {
    config::set_config(KeygenConfig {
        api_url: env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string()),
        account: env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"),
        product: env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set"),
        license_key: Some(license_key),
        public_key: env::var("KEYGEN_PUBLIC_KEY").ok(),
        ..KeygenConfig::default()
    })
}

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

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    let license_key = env::var("KEYGEN_LICENSE_KEY").expect("KEYGEN_LICENSE_KEY must be set");
    let artifact_name = env::var("KEYGEN_ARTIFACT").expect("KEYGEN_ARTIFACT must be set");
    configure(license_key)?;
    let mut failures = 0;

    let releases = report(
        &mut failures,
        "Release::list sees published 1.0.0 and 1.1.0",
        Release::list(None)
            .await
            .map_err(|e| e.to_string())
            .and_then(|releases| {
                for r in &releases {
                    println!(
                        "     {} {:?} {:?} ({})",
                        r.version, r.status, r.channel, r.id
                    );
                }
                let versions: Vec<_> = releases.iter().map(|r| r.version.as_str()).collect();
                if versions.contains(&"1.0.0") && versions.contains(&"1.1.0") {
                    Ok(releases)
                } else {
                    Err(format!("got versions {versions:?}"))
                }
            }),
    )
    .unwrap_or_default();

    let upgrade = releases.into_iter().find(|r| r.version == "1.1.0");
    if let Some(upgrade) = upgrade {
        report(
            &mut failures,
            "Release::get by ID",
            Release::get(&upgrade.id)
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| {
                    (r.version == "1.1.0")
                        .then_some(())
                        .ok_or(format!("got {}", r.version))
                }),
        );

        let artifact = report(
            &mut failures,
            "Release::artifacts has the uploaded artifact with checksum and signature",
            upgrade
                .artifacts(None)
                .await
                .map_err(|e| e.to_string())
                .and_then(|artifacts| {
                    for a in &artifacts {
                        println!(
                            "     {} {:?} size={:?} platform={:?} arch={:?} checksum={} signature={}",
                            a.filename,
                            a.status,
                            a.filesize,
                            a.platform,
                            a.arch,
                            a.checksum.is_some(),
                            a.signature.is_some()
                        );
                    }
                    artifacts
                        .into_iter()
                        .find(|a| a.filename == artifact_name)
                        .ok_or(format!("{artifact_name} not found"))
                        .and_then(|a| {
                            if a.checksum.is_some() && a.signature.is_some() {
                                Ok(a)
                            } else {
                                Err("checksum or signature is missing".to_string())
                            }
                        })
                }),
        );

        if let Some(artifact) = artifact {
            report(
                &mut failures,
                "Artifact::get by ID",
                Artifact::get(&artifact.id)
                    .await
                    .map_err(|e| e.to_string())
                    .map(|_| ()),
            );
        }
    }

    report(
        &mut failures,
        "Artifact::list",
        Artifact::list(None)
            .await
            .map_err(|e| e.to_string())
            .map(|a| println!("     {} artifact(s)", a.len())),
    );
    report(
        &mut failures,
        "Package::list",
        Package::list(None)
            .await
            .map_err(|e| e.to_string())
            .map(|p| println!("     {} package(s)", p.len())),
    );
    report(
        &mut failures,
        "Channel::list",
        Channel::list(None)
            .await
            .map_err(|e| e.to_string())
            .map(|c| println!("     {:?}", c.iter().map(|c| &c.key).collect::<Vec<_>>())),
    );
    report(
        &mut failures,
        "Arch::list",
        Arch::list(None)
            .await
            .map_err(|e| e.to_string())
            .map(|a| println!("     {:?}", a.iter().map(|a| &a.key).collect::<Vec<_>>())),
    );
    report(
        &mut failures,
        "Platform::list",
        Platform::list(None)
            .await
            .map_err(|e| e.to_string())
            .map(|p| println!("     {:?}", p.iter().map(|p| &p.key).collect::<Vec<_>>())),
    );

    configure("INVALID-LICENSE-KEY".to_string())?;
    report(
        &mut failures,
        "Release::list with an invalid license key is an error",
        match Release::list(None).await {
            Ok(r) => Err(format!("got {} release(s)", r.len())),
            Err(e) => {
                println!("     {e}");
                Ok(())
            }
        },
    );

    println!("\n{failures} failure(s)");
    Ok(())
}
