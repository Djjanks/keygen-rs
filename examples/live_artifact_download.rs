//! Local live check, not part of the PR: `Release::download_artifact_to` and
//! `KeygenClient::download_artifact_to` against the real account — signing key,
//! signature context (product), `on_progress`, `.part` cleanup, and every
//! artifact error. For checksum/signature errors the uploaded artifact is
//! temporarily patched with the admin token (if `KEYGEN_ADMIN_TOKEN` is set)
//! and restored at the end.
//! Needs commit "feat(release): download artifacts with checksum and signature verification".
//!
//! cargo run --example live_artifact_download --no-default-features --features rustls,license-key

use base64::Engine;
use keygen_rs::{
    artifact::Artifact,
    config::{self, KeygenConfig},
    errors::{ApiErrorKind, Error},
    keygen_client::KeygenClient,
    release::{ArtifactDownloadOptions, Release},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Valid key from `keygen genkey`-like generation, but not the one that signed the artifact.
const OTHER_SIGNING_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const OTHER_PRODUCT: &str = "00000000-0000-4000-8000-000000000000";

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

fn report(failures: &mut u32, name: &str, result: Result<(), String>) {
    match result {
        Ok(()) => println!("PASS {name}"),
        Err(err) => {
            println!("FAIL {name}: {err}");
            *failures += 1;
        }
    }
}

fn part_path(path: &Path) -> PathBuf {
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    PathBuf::from(part)
}

fn options(key: Option<&str>) -> Option<ArtifactDownloadOptions> {
    Some(ArtifactDownloadOptions {
        public_key: key.map(str::to_string),
        on_progress: None,
    })
}

/// Download succeeded: file is at `path` with the expected checksum, no `.part`.
fn expect_file(result: Result<Artifact, Error>, path: &Path, checksum: &str) -> Result<(), String> {
    let artifact = result.map_err(|e| format!("{e:?}"))?;
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let computed = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha512::digest(&bytes));
    if computed != checksum.trim_end_matches('=') {
        return Err(format!("file checksum {computed}"));
    }
    if part_path(path).exists() {
        return Err(".part left behind".to_string());
    }
    if Some(bytes.len() as u64) != artifact.filesize {
        return Err(format!(
            "{} bytes, filesize {:?}",
            bytes.len(),
            artifact.filesize
        ));
    }
    Ok(())
}

/// Download failed with the expected error; the previous content of `path`
/// (`previous`, `None` = no file) is untouched and no `.part` is left.
fn expect_err(
    result: Result<Artifact, Error>,
    path: &Path,
    previous: Option<&[u8]>,
    expected: impl Fn(&Error) -> bool,
) -> Result<(), String> {
    match result {
        Ok(_) => return Err("download succeeded".to_string()),
        Err(e) if expected(&e) => println!("     {e:?}"),
        Err(e) => return Err(format!("unexpected error {e:?}")),
    }
    if part_path(path).exists() {
        return Err(".part left behind".to_string());
    }
    match (previous, std::fs::read(path).ok()) {
        (None, None) => Ok(()),
        (Some(previous), Some(current)) if previous == current.as_slice() => Ok(()),
        (_, current) => Err(format!(
            "destination changed: {:?} bytes",
            current.map(|c| c.len())
        )),
    }
}

/// Raw admin PATCH of the artifact, so `null` can be set too (`UpdateArtifactRequest` skips `None`).
async fn patch_artifact(id: &str, attributes: Value) -> Result<Value, String> {
    let api_url =
        env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string());
    let account = env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set");
    let token = env::var("KEYGEN_ADMIN_TOKEN").expect("KEYGEN_ADMIN_TOKEN must be set");
    let response = reqwest::Client::new()
        .patch(format!("{api_url}/v1/accounts/{account}/artifacts/{id}"))
        .bearer_auth(token)
        .header("content-type", "application/vnd.api+json")
        .header("accept", "application/vnd.api+json")
        .body(json!({ "data": { "type": "artifacts", "attributes": attributes } }).to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let body: Value = response.json().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("status {status}: {body}"));
    }
    Ok(body["data"]["attributes"].clone())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    config::set_config(license_config())?;
    let artifact_name = env::var("KEYGEN_ARTIFACT").expect("KEYGEN_ARTIFACT must be set");
    let signing_key =
        env::var("KEYGEN_SIGNING_PUBLIC_KEY").expect("KEYGEN_SIGNING_PUBLIC_KEY must be set");
    let account_key = env::var("KEYGEN_PUBLIC_KEY").expect("KEYGEN_PUBLIC_KEY must be set");
    let signing_key = signing_key.as_str();
    let mut failures = 0;

    let dir = env::temp_dir().join(format!("keygen-rs-live-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join(&artifact_name);
    let reset = |path: &Path| {
        let _ = std::fs::remove_file(path);
    };

    let release = Release::list(None)
        .await?
        .into_iter()
        .find(|r| r.version == "1.1.0")
        .expect("release 1.1.0 must be published");
    println!("     release 1.1.0 product_id {:?}", release.product_id);
    let listed = release
        .artifacts(None)
        .await?
        .into_iter()
        .find(|a| a.filename == artifact_name)
        .expect("artifact must be uploaded to 1.1.0");
    let checksum = listed.checksum.clone().expect("artifact has a checksum");
    let signature = listed.signature.clone().expect("artifact is signed");

    // --- Successful downloads ---

    let progress = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&progress);
    let result = release
        .download_artifact_to(
            &artifact_name,
            &path,
            Some(ArtifactDownloadOptions {
                public_key: Some(signing_key.to_string()),
                on_progress: Some(Box::new(move |done, total| {
                    sink.lock().unwrap().push((done, total))
                })),
            }),
        )
        .await;
    report(
        &mut failures,
        "download by filename with the signing key",
        expect_file(result, &path, &checksum),
    );
    report(
        &mut failures,
        "on_progress: increasing, ends at (filesize, Some(filesize))",
        {
            let calls = progress.lock().unwrap().clone();
            println!("     {calls:?}");
            let size = listed.filesize;
            let increasing = calls.windows(2).all(|w| w[0].0 < w[1].0);
            match calls.last() {
                Some(&(done, total)) if increasing && Some(done) == size && total == size => Ok(()),
                _ => Err(format!("filesize {size:?}")),
            }
        },
    );

    // Overwrites the file from the previous step.
    let result = release
        .download_artifact_to(&listed.id, &path, options(Some(signing_key)))
        .await;
    report(
        &mut failures,
        "download by artifact ID over an existing file",
        expect_file(result, &path, &checksum),
    );

    reset(&path);
    let result = release
        .download_artifact_to(&artifact_name, &path, None)
        .await;
    report(
        &mut failures,
        "download without a signing key (checksum only)",
        expect_file(result, &path, &checksum),
    );

    reset(&path);
    let client = KeygenClient::new(license_config())?;
    let result = client
        .download_artifact_to(&release, &artifact_name, &path, options(Some(signing_key)))
        .await;
    report(
        &mut failures,
        "KeygenClient::download_artifact_to with the signing key",
        expect_file(result, &path, &checksum),
    );

    // --- Signature context (product) ---

    reset(&path);
    let other_product_client = KeygenClient::new(KeygenConfig {
        product: OTHER_PRODUCT.to_string(),
        ..license_config()
    })?;
    let result = other_product_client
        .download_artifact_to(&release, &artifact_name, &path, options(Some(signing_key)))
        .await;
    report(
        &mut failures,
        "another product in config: context comes from the release's product",
        expect_file(result, &path, &checksum),
    );

    reset(&path);
    let without_product = Release {
        product_id: None,
        ..release.clone()
    };
    let result = without_product
        .download_artifact_to(&artifact_name, &path, options(Some(signing_key)))
        .await;
    report(
        &mut failures,
        "release without product: context falls back to config product",
        expect_file(result, &path, &checksum),
    );

    reset(&path);
    let other_product_release = Release {
        product_id: Some(OTHER_PRODUCT.to_string()),
        ..release.clone()
    };
    let result = other_product_release
        .download_artifact_to(&artifact_name, &path, options(Some(signing_key)))
        .await;
    report(
        &mut failures,
        "release of another product (wrong context) -> ArtifactSignatureInvalid",
        expect_err(result, &path, None, |e| {
            matches!(e, Error::ArtifactSignatureInvalid(_))
        }),
    );

    let result = other_product_client
        .download_artifact_to(
            &without_product,
            &artifact_name,
            &path,
            options(Some(signing_key)),
        )
        .await;
    report(
        &mut failures,
        "release without product + another product in config -> ArtifactSignatureInvalid",
        expect_err(result, &path, None, |e| {
            matches!(e, Error::ArtifactSignatureInvalid(_))
        }),
    );

    let no_product_client = KeygenClient::new(KeygenConfig {
        product: String::new(),
        ..license_config()
    })?;
    let result = no_product_client
        .download_artifact_to(
            &without_product,
            &artifact_name,
            &path,
            options(Some(signing_key)),
        )
        .await;
    report(
        &mut failures,
        "no product anywhere + signing key -> ArtifactSignatureInvalid (context unknown)",
        expect_err(result, &path, None, |e| {
            matches!(e, Error::ArtifactSignatureInvalid(_))
        }),
    );

    // --- Wrong keys; an existing destination file must survive ---

    let previous: &[u8] = b"previous version";
    std::fs::write(&path, previous).expect("write previous file");

    let result = release
        .download_artifact_to(&artifact_name, &path, options(Some(OTHER_SIGNING_KEY)))
        .await;
    report(
        &mut failures,
        "another signing key -> ArtifactSignatureInvalid, existing file kept",
        expect_err(result, &path, Some(previous), |e| {
            matches!(e, Error::ArtifactSignatureInvalid(_))
        }),
    );

    for (name, key) in [
        ("account public key", account_key.clone()),
        ("account public key, uppercase", account_key.to_uppercase()),
        ("non-hex key", "not-hex".to_string()),
        ("short key", signing_key[..8].to_string()),
    ] {
        let result = release
            .download_artifact_to(&artifact_name, &path, options(Some(&key)))
            .await;
        report(
            &mut failures,
            &format!("{name} -> ArtifactPublicKeyInvalid, existing file kept"),
            expect_err(result, &path, Some(previous), |e| {
                matches!(e, Error::ArtifactPublicKeyInvalid(_))
            }),
        );
    }

    let result = release
        .download_artifact_to(
            "missing-file.txt",
            dir.join("missing-file.txt"),
            options(Some(signing_key)),
        )
        .await;
    report(
        &mut failures,
        "missing artifact -> API NotFound, nothing left",
        expect_err(result, &dir.join("missing-file.txt"), None, |e| {
            e.api_error_kind() == ApiErrorKind::NotFound
        }),
    );

    // --- Tampered artifact (admin) ---

    if env::var("KEYGEN_ADMIN_TOKEN").is_err() {
        println!("SKIP tampered artifact checks: KEYGEN_ADMIN_TOKEN is not set");
    } else {
        // Valid base64 values that do not belong to this file.
        let wrong_checksum = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(Sha512::digest(b"not the artifact"));
        let wrong_signature = base64::engine::general_purpose::STANDARD_NO_PAD.encode([7u8; 64]);

        type Check<'a> = (&'static str, Value, Option<&'a str>, fn(&Error) -> bool);
        let cases: Vec<Check> = vec![
            (
                "wrong checksum -> ArtifactChecksumMismatch",
                json!({ "checksum": wrong_checksum }),
                None,
                |e| matches!(e, Error::ArtifactChecksumMismatch),
            ),
            (
                "no checksum -> ArtifactChecksumMissing",
                json!({ "checksum": null }),
                None,
                |e| matches!(e, Error::ArtifactChecksumMissing),
            ),
            (
                "wrong signature -> ArtifactSignatureInvalid",
                json!({ "checksum": checksum, "signature": wrong_signature }),
                Some(signing_key),
                |e| matches!(e, Error::ArtifactSignatureInvalid(_)),
            ),
            (
                "malformed signature -> ArtifactSignatureInvalid",
                json!({ "signature": "not base64!" }),
                Some(signing_key),
                |e| matches!(e, Error::ArtifactSignatureInvalid(_)),
            ),
            (
                "no signature + signing key -> ArtifactSignatureMissing",
                json!({ "signature": null }),
                Some(signing_key),
                |e| matches!(e, Error::ArtifactSignatureMissing),
            ),
        ];

        for (name, attributes, key, expected) in cases {
            match patch_artifact(&listed.id, attributes).await {
                Ok(_) => {
                    let result = release
                        .download_artifact_to(&artifact_name, &path, options(key))
                        .await;
                    report(
                        &mut failures,
                        &format!("{name}, existing file kept"),
                        expect_err(result, &path, Some(previous), expected),
                    );
                }
                Err(e) => report(&mut failures, name, Err(format!("patch failed: {e}"))),
            }
        }

        // Signature is still null here: without a key only the checksum matters.
        reset(&path);
        let result = release
            .download_artifact_to(&artifact_name, &path, None)
            .await;
        report(
            &mut failures,
            "no signature, no signing key -> Ok (checksum only)",
            expect_file(result, &path, &checksum),
        );

        // The signature covers the SHA-512 of the file, so it is enough on its own.
        match patch_artifact(
            &listed.id,
            json!({ "checksum": null, "signature": signature }),
        )
        .await
        {
            Ok(_) => {
                reset(&path);
                let result = release
                    .download_artifact_to(&artifact_name, &path, options(Some(signing_key)))
                    .await;
                report(
                    &mut failures,
                    "no checksum + valid signature -> Ok (signature only)",
                    expect_file(result, &path, &checksum),
                );
            }
            Err(e) => report(
                &mut failures,
                "no checksum + valid signature",
                Err(format!("patch failed: {e}")),
            ),
        }

        let restored = patch_artifact(
            &listed.id,
            json!({ "checksum": checksum, "signature": signature }),
        )
        .await;
        report(
            &mut failures,
            "restore checksum and signature",
            match &restored {
                Ok(a)
                    if a["checksum"] == checksum.as_str()
                        && a["signature"] == signature.as_str() =>
                {
                    Ok(())
                }
                Ok(a) => Err(format!(
                    "checksum {} signature {}",
                    a["checksum"], a["signature"]
                )),
                Err(e) => Err(format!(
                    "{e}\n     restore manually: checksum {checksum} signature {signature}"
                )),
            },
        );

        reset(&path);
        let result = release
            .download_artifact_to(&artifact_name, &path, options(Some(signing_key)))
            .await;
        report(
            &mut failures,
            "restored artifact downloads with the signing key",
            expect_file(result, &path, &checksum),
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
    println!("\n{failures} failure(s)");
    Ok(())
}
