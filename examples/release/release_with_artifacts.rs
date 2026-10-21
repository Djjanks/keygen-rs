use keygen_rs::{
    artifact::{Artifact, CreateArtifactRequest},
    config::{self, KeygenConfig},
    errors::Error,
    release::{CreateReleaseRequest, Release, ReleaseChannel, ReleaseStatus},
};
use std::{env, path::Path};

/// Publishes a release the way a CI job would: create a draft release,
/// upload its artifacts, then publish it.
///
/// ARTIFACT_PATHS is a comma-separated list of files to upload. Their platform and
/// arch are not set; set them per file when the release has builds for several targets.
///
/// If an upload fails, the draft release is left as is and can be deleted or retried.
#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();

    config::set_config(KeygenConfig {
        api_url: env::var("KEYGEN_API_URL").unwrap_or_else(|_| "https://api.keygen.sh".to_string()),
        account: env::var("KEYGEN_ACCOUNT").expect("KEYGEN_ACCOUNT must be set"),
        token: Some(env::var("KEYGEN_ADMIN_TOKEN").expect("KEYGEN_ADMIN_TOKEN must be set")),
        ..KeygenConfig::default()
    })?;

    let product_id = env::var("KEYGEN_PRODUCT").expect("KEYGEN_PRODUCT must be set");
    let paths = env::var("ARTIFACT_PATHS").expect("ARTIFACT_PATHS must be set");
    let version = env::var("RELEASE_VERSION")
        .unwrap_or_else(|_| format!("1.0.{}", chrono::Utc::now().timestamp() % 1000));

    let release = Release::create(CreateReleaseRequest {
        version: version.clone(),
        channel: ReleaseChannel::Stable,
        product_id,
        name: Some(format!("v{version}")),
        description: None,
        status: Some(ReleaseStatus::Draft),
        tag: Some(format!("v{version}")),
        metadata: None,
    })
    .await?;
    println!("Created draft release {} ({})", release.version, release.id);

    for path in paths.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let filename = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("artifact path must point to a file")
            .to_string();

        let artifact = Artifact::create_and_upload(
            CreateArtifactRequest {
                filename,
                release_id: release.id.clone(),
                filetype: Path::new(path)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(str::to_string),
                filesize: None,
                platform: None,
                arch: None,
                signature: None,
                checksum: None,
                metadata: None,
            },
            path,
            None,
        )
        .await?;
        println!(
            "  Uploaded {} ({:?} bytes, status {:?})",
            artifact.filename, artifact.filesize, artifact.status
        );
    }

    let release = release.publish().await?;
    println!(
        "Published release {} ({:?})",
        release.version, release.status
    );

    Ok(())
}
