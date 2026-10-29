//! Local live check, not part of the PR: `Artifact::create_and_upload`
//! with the admin token, then downloads by license key as a client
//! app does. Uploads temporary artifacts to release 1.1.0 and deletes them at the end.
//! The signature is made with the private key from `keygen genkey`
//! (`KEYGEN_SIGNING_KEY_PATH`, default `%USERPROFILE%\.keygen-rs-test\keygen.key`).
//! Needs commit "feat(artifact): upload artifact files".
//!
//! cargo run --example live_artifact_upload --all-features

use base64::Engine;
use ed25519_dalek::SigningKey;
use keygen_rs::{
    artifact::{Artifact, ArtifactStatus, ArtifactUploadOptions, CreateArtifactRequest},
    config::{self, KeygenConfig},
    errors::Error,
    keygen_client::KeygenClient,
    release::{ArtifactDownloadOptions, Release},
};
use sha2::{Digest, Sha512};
use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

const LARGE_SIZE: usize = 5 * 1024 * 1024;

fn api_url() -> String {
    env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string())
}

fn license_config() -> KeygenConfig {
    KeygenConfig {
        api_url: api_url(),
        account: env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"),
        product: env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set"),
        license_key: Some(env::var("KEYGEN_LICENSE_KEY").expect("KEYGEN_LICENSE_KEY must be set")),
        public_key: env::var("KEYGEN_PUBLIC_KEY").ok(),
        ..KeygenConfig::default()
    }
}

fn admin_config() -> KeygenConfig {
    KeygenConfig {
        api_url: api_url(),
        account: env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"),
        product: env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set"),
        token: Some(env::var("KEYGEN_ADMIN_TOKEN").expect("KEYGEN_ADMIN_TOKEN must be set")),
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

fn checksum_of(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha512::digest(bytes))
}

/// Private key from `keygen genkey`: hex of seed (32 bytes) + public key (32 bytes).
fn signing_key() -> SigningKey {
    let path = env::var("KEYGEN_SIGNING_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env::var("USERPROFILE").expect("USERPROFILE must be set"))
                .join(".keygen-rs-test")
                .join("keygen.key")
        });
    let hex_key = std::fs::read_to_string(&path).expect("read signing key");
    let bytes = hex::decode(hex_key.trim()).expect("signing key is hex");
    let seed: [u8; 32] = bytes[..32]
        .try_into()
        .expect("signing key has a 32-byte seed");
    SigningKey::from_bytes(&seed)
}

/// Ed25519ph over SHA-512 of the file with the product ID as context, as `keygen upload` signs.
fn sign(key: &SigningKey, bytes: &[u8], product: &str) -> String {
    let mut prehash = Sha512::new();
    prehash.update(bytes);
    let signature = key
        .sign_prehashed(prehash, Some(product.as_bytes()))
        .expect("sign");
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature.to_bytes())
}

fn request(release: &Release, filename: &str, signature: Option<String>) -> CreateArtifactRequest {
    CreateArtifactRequest {
        filename: filename.to_string(),
        release_id: release.id.clone(),
        filetype: Some("bin".to_string()),
        filesize: None,
        platform: None,
        arch: None,
        signature,
        checksum: None,
        metadata: None,
    }
}

/// Keygen Cloud moves an uploaded artifact from `WAITING` to `UPLOADED` with a delay
/// (~30s observed); until then license key downloads get `NOT_FOUND`.
async fn wait_uploaded(id: &str) -> Result<Artifact, String> {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(120) {
        let artifact = Artifact::get(id).await.map_err(|e| format!("{e:?}"))?;
        if artifact.status == ArtifactStatus::Uploaded {
            println!("     UPLOADED after {}s", started.elapsed().as_secs());
            return Ok(artifact);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err("still not UPLOADED after 120s".to_string())
}

/// Uploaded artifact has the local filesize and the SHA-512 checksum of the file.
fn expect_uploaded(artifact: &Artifact, bytes: &[u8], signed: bool) -> Result<(), String> {
    let checksum = artifact.checksum.as_deref().unwrap_or_default();
    if artifact.filesize != Some(bytes.len() as u64) {
        return Err(format!("filesize {:?}", artifact.filesize));
    }
    if checksum.trim_end_matches('=') != checksum_of(bytes) {
        return Err(format!("checksum {checksum}"));
    }
    if artifact.signature.is_some() != signed {
        return Err(format!("signature {:?}", artifact.signature));
    }
    Ok(())
}

/// Progress of the large file: more than one call, increasing, ending at its size.
fn check_progress(calls: &[(u64, Option<u64>)]) -> Result<(), String> {
    let total = Some(LARGE_SIZE as u64);
    println!(
        "     {} calls, first {:?}, last {:?}",
        calls.len(),
        calls.first(),
        calls.last()
    );
    let increasing = calls.windows(2).all(|w| w[0].0 < w[1].0);
    let totals = calls.iter().all(|c| c.1 == total);
    match calls.last() {
        Some(&(done, _)) if calls.len() > 1 && increasing && totals && Some(done) == total => {
            Ok(())
        }
        _ => Err("unexpected progress".to_string()),
    }
}

async fn download(
    client: &KeygenClient,
    release: &Release,
    filename: &str,
    path: &Path,
    public_key: Option<&str>,
) -> Result<Vec<u8>, Error> {
    client
        .download_artifact_to(
            release,
            filename,
            path,
            Some(ArtifactDownloadOptions {
                public_key: public_key.map(str::to_string),
                on_progress: None,
            }),
        )
        .await?;
    Ok(std::fs::read(path).expect("read downloaded file"))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    // Uploads use the global config (admin), downloads a license key client.
    config::set_config(admin_config())?;
    let user = KeygenClient::new(license_config())?;
    let public_key =
        env::var("KEYGEN_SIGNING_PUBLIC_KEY").expect("KEYGEN_SIGNING_PUBLIC_KEY must be set");
    let product = env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set");
    let mut failures = 0;

    let key = signing_key();
    report(
        &mut failures,
        "private key matches KEYGEN_SIGNING_PUBLIC_KEY",
        (hex::encode(key.verifying_key().to_bytes()) == public_key.to_lowercase())
            .then_some(())
            .ok_or("different key pair".to_string()),
    );

    let release = Release::list(None)
        .await?
        .into_iter()
        .find(|r| r.version == "1.1.0")
        .expect("release 1.1.0 must exist");
    let context = release.product_id.clone().unwrap_or(product);

    let dir = env::temp_dir().join(format!("keygen-rs-live-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let run = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let mut created: Vec<Artifact> = Vec::new();

    // --- Unsigned small file: create_and_upload ---

    let small_name = format!("live-upload-{run}-small.bin");
    let small: Vec<u8> = format!("live upload {run}\n").into_bytes();
    let small_path = dir.join(&small_name);
    std::fs::write(&small_path, &small).expect("write small file");

    match Artifact::create_and_upload(request(&release, &small_name, None), &small_path, None).await
    {
        Ok(artifact) => {
            println!("     returned status {:?}", artifact.status);
            created.push(artifact.clone());
            let result = match wait_uploaded(&artifact.id).await {
                Ok(uploaded) => expect_uploaded(&uploaded, &small, false),
                Err(e) => Err(e),
            };
            report(
                &mut failures,
                "create_and_upload unsigned: UPLOADED, filesize and checksum computed",
                result,
            );

            let out = dir.join("small.out");
            report(
                &mut failures,
                "download unsigned by license key without signing key",
                match download(&user, &release, &small_name, &out, None).await {
                    Ok(bytes) if bytes == small => Ok(()),
                    Ok(bytes) => Err(format!("{} bytes differ", bytes.len())),
                    Err(e) => Err(format!("{e:?}")),
                },
            );
            report(
                &mut failures,
                "download unsigned with signing key -> ArtifactSignatureMissing",
                match download(
                    &user,
                    &release,
                    &small_name,
                    &dir.join("small2.out"),
                    Some(&public_key),
                )
                .await
                {
                    Err(Error::ArtifactSignatureMissing) => Ok(()),
                    other => Err(format!("{:?}", other.map(|b| b.len()))),
                },
            );

            report(
                &mut failures,
                "same filename again -> error, first artifact intact",
                match Artifact::create_and_upload(
                    request(&release, &small_name, None),
                    &small_path,
                    None,
                )
                .await
                {
                    Ok(dup) => {
                        created.push(dup.clone());
                        Err(format!("duplicate created {}", dup.id))
                    }
                    Err(e) => {
                        println!("     {e}");
                        match download(&user, &release, &small_name, &dir.join("small3.out"), None)
                            .await
                        {
                            Ok(bytes) if bytes == small => Ok(()),
                            other => Err(format!("first artifact: {:?}", other.map(|b| b.len()))),
                        }
                    }
                },
            );
        }
        Err(e) => report(
            &mut failures,
            "create_and_upload unsigned",
            Err(format!("{e:?}")),
        ),
    }

    // --- Signed large file: create_and_upload + on_progress ---

    let large_name = format!("live-upload-{run}-large.bin");
    let large: Vec<u8> = (0..LARGE_SIZE).map(|i| (i * 31 % 251) as u8).collect();
    let large_path = dir.join(&large_name);
    std::fs::write(&large_path, &large).expect("write large file");
    let signature = sign(&key, &large, &context);

    let upload_progress = Arc::new(Mutex::new(Vec::new()));
    let upload_sink = Arc::clone(&upload_progress);
    let upload_options = ArtifactUploadOptions {
        on_progress: Some(Box::new(move |done, total| {
            upload_sink.lock().unwrap().push((done, Some(total)))
        })),
    };
    match Artifact::create_and_upload(
        request(&release, &large_name, Some(signature)),
        &large_path,
        Some(upload_options),
    )
    .await
    {
        Ok(artifact) => {
            created.push(artifact.clone());
            report(
                &mut failures,
                "upload on_progress: many calls, increasing, ends at filesize",
                check_progress(&upload_progress.lock().unwrap()),
            );
            report(
                &mut failures,
                "create_and_upload signed 5 MiB: UPLOADED, checksum computed, signature stored",
                match wait_uploaded(&artifact.id).await {
                    Ok(uploaded) => expect_uploaded(&uploaded, &large, true),
                    Err(e) => Err(e),
                },
            );

            let progress = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&progress);
            let out = dir.join("large.out");
            let result = user
                .download_artifact_to(
                    &release,
                    &large_name,
                    &out,
                    Some(ArtifactDownloadOptions {
                        public_key: Some(public_key.clone()),
                        on_progress: Some(Box::new(move |done, total| {
                            sink.lock().unwrap().push((done, total))
                        })),
                    }),
                )
                .await;
            report(
                &mut failures,
                "download signed by license key with signing key",
                match result {
                    Ok(_) if std::fs::read(&out).ok().as_deref() == Some(large.as_slice()) => {
                        Ok(())
                    }
                    Ok(_) => Err("downloaded bytes differ".to_string()),
                    Err(e) => Err(format!("{e:?}")),
                },
            );
            report(
                &mut failures,
                "download on_progress: many calls, increasing, ends at filesize",
                check_progress(&progress.lock().unwrap()),
            );
        }
        Err(e) => report(
            &mut failures,
            "create_and_upload signed",
            Err(format!("{e:?}")),
        ),
    }

    // --- filesize and checksum given in the request ---

    let step_name = format!("live-upload-{run}-given.bin");
    let step: Vec<u8> = format!("given checksum {run}\n").into_bytes();
    let step_path = dir.join(&step_name);
    std::fs::write(&step_path, &step).expect("write file");
    let mut step_request = request(&release, &step_name, Some(sign(&key, &step, &context)));
    step_request.filesize = Some(step.len() as u64);
    step_request.checksum = Some(checksum_of(&step));

    match Artifact::create_and_upload(step_request, &step_path, None).await {
        Ok(artifact) => {
            created.push(artifact.clone());
            report(
                &mut failures,
                "create_and_upload with given filesize/checksum: UPLOADED",
                match wait_uploaded(&artifact.id).await {
                    Ok(uploaded) => expect_uploaded(&uploaded, &step, true),
                    Err(e) => Err(e),
                },
            );
            report(
                &mut failures,
                "download it with signing key",
                match download(
                    &user,
                    &release,
                    &step_name,
                    &dir.join("step.out"),
                    Some(&public_key),
                )
                .await
                {
                    Ok(bytes) if bytes == step => Ok(()),
                    other => Err(format!("{:?}", other.map(|b| b.len()))),
                },
            );
        }
        Err(e) => report(
            &mut failures,
            "create_and_upload with given filesize/checksum",
            Err(format!("{e:?}")),
        ),
    }

    // --- Missing local file: nothing is created ---

    let missing_name = format!("live-upload-{run}-missing.bin");
    let result = Artifact::create_and_upload(
        request(&release, &missing_name, None),
        dir.join(&missing_name),
        None,
    )
    .await;
    let leftover = release
        .artifacts(None)
        .await?
        .into_iter()
        .find(|a| a.filename == missing_name);
    report(
        &mut failures,
        "missing local file -> error, no artifact created",
        match (result, leftover) {
            (Err(e), None) => {
                println!("     {e}");
                Ok(())
            }
            (Ok(a), _) | (Err(_), Some(a)) => {
                created.push(a.clone());
                Err(format!("artifact {} created", a.id))
            }
        },
    );

    // --- Cleanup ---

    let mut cleanup = Ok(());
    for artifact in &created {
        if let Err(e) = artifact.delete().await {
            cleanup = Err(format!(
                "delete {} ({}): {e}",
                artifact.id, artifact.filename
            ));
        }
    }
    let remaining: Vec<String> = release
        .artifacts(None)
        .await?
        .into_iter()
        .filter(|a| a.filename.starts_with(&format!("live-upload-{run}")))
        .map(|a| a.filename)
        .collect();
    report(
        &mut failures,
        "cleanup: temporary artifacts deleted",
        cleanup.and_then(|()| {
            remaining
                .is_empty()
                .then_some(())
                .ok_or(format!("remaining {remaining:?}"))
        }),
    );

    let _ = std::fs::remove_dir_all(&dir);
    println!("\n{failures} failure(s)");
    Ok(())
}
