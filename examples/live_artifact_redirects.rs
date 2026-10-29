//! Local live check, not part of the PR: the client does not follow redirects,
//! so artifact responses (303) expose `Location` and the artifact body.
//! Needs commit "feat(release)!: return the artifact and API errors from download_artifact".
//!
//! cargo run --example live_artifact_redirects --no-default-features --features rustls,license-key

use base64::Engine;
use keygen_rs::{
    artifact::Artifact,
    config::{self, KeygenConfig},
    errors::Error,
    release::Release,
};
use sha2::{Digest, Sha512};
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    config::set_config(KeygenConfig {
        api_url: env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string()),
        account: env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"),
        product: env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set"),
        license_key: Some(env::var("KEYGEN_LICENSE_KEY").expect("KEYGEN_LICENSE_KEY must be set")),
        public_key: env::var("KEYGEN_PUBLIC_KEY").ok(),
        ..KeygenConfig::default()
    })?;
    let artifact_name = env::var("KEYGEN_ARTIFACT").expect("KEYGEN_ARTIFACT must be set");
    let mut failures = 0;

    let release = Release::list(None)
        .await?
        .into_iter()
        .find(|r| r.version == "1.1.0")
        .expect("release 1.1.0 must be published");
    let listed = release
        .artifacts(None)
        .await?
        .into_iter()
        .find(|a| a.filename == artifact_name)
        .expect("artifact must be uploaded to 1.1.0");

    report(
        &mut failures,
        "Artifact::get by ID (303 is not followed, body is parsed)",
        Artifact::get(&listed.id)
            .await
            .map_err(|e| e.to_string())
            .and_then(|a| {
                (a.id == listed.id && a.checksum.is_some())
                    .then_some(())
                    .ok_or(format!("unexpected artifact {} {:?}", a.id, a.checksum))
            }),
    );

    let download = report(
        &mut failures,
        "download_artifact by filename: Location + artifact body",
        release
            .download_artifact(&artifact_name)
            .await
            .map_err(|e| e.to_string())
            .and_then(|d| {
                let host = url::Url::parse(&d.location)
                    .map_err(|e| e.to_string())?
                    .host_str()
                    .unwrap_or_default()
                    .to_string();
                println!("     location host: {host}");
                match &d.artifact {
                    Some(a)
                        if a.id == listed.id && a.checksum.is_some() && a.signature.is_some() =>
                    {
                        Ok(d)
                    }
                    other => Err(format!("unexpected artifact body: {other:?}")),
                }
            }),
    );

    report(
        &mut failures,
        "download_artifact by artifact ID",
        release
            .download_artifact(&listed.id)
            .await
            .map_err(|e| e.to_string())
            .and_then(|d| {
                d.artifact
                    .filter(|a| a.id == listed.id)
                    .map(|_| ())
                    .ok_or("no artifact body".to_string())
            }),
    );

    report(
        &mut failures,
        "download_artifact for a missing file is an error",
        match release.download_artifact("missing-file.txt").await {
            Ok(d) => Err(format!("got location {}", d.location)),
            Err(e) => {
                println!("     {e}");
                Ok(())
            }
        },
    );

    if let Some(download) = download {
        let artifact = download.artifact.expect("checked above");
        report(
            &mut failures,
            "Location serves the file without Keygen auth, SHA-512 matches checksum",
            async {
                let response = reqwest::get(&download.location)
                    .await
                    .map_err(|e| e.to_string())?;
                let status = response.status();
                let bytes = response.bytes().await.map_err(|e| e.to_string())?;
                if !status.is_success() {
                    return Err(format!("status {status}"));
                }
                let checksum =
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha512::digest(&bytes));
                println!(
                    "     {} bytes (filesize {:?}), checksum {}",
                    bytes.len(),
                    artifact.filesize,
                    artifact.checksum.as_deref().unwrap_or_default()
                );
                let expected = artifact.checksum.as_deref().unwrap_or_default();
                if checksum == expected.trim_end_matches('=') {
                    Ok(())
                } else {
                    Err(format!("computed {checksum}"))
                }
            }
            .await,
        );
    }

    println!("\n{failures} failure(s)");
    Ok(())
}
