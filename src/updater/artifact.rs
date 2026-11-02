use crate::{
    common::{display_version_from_release_id, release_id_from_update_url},
    hbbs_http::create_http_client_with_url_strict,
    update_metadata::{UpdateArtifactQuery, UpdateMetadataRequirements, VerifiedUpdateArtifact},
};
use hbb_common::{bail, ResultType};
use std::{
    io::Read,
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

const UPDATE_SIDECAR_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const UPDATE_METADATA_SIDECAR_MAX_BYTES: u64 = 1024 * 1024;

lazy_static::lazy_static! {
    static ref VERIFIED_UPDATE_ARTIFACT: Mutex<Option<VerifiedUpdateArtifact>> = Mutex::new(None);
}

pub(crate) fn current_update_platform() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::consts::OS
    }
}

pub(crate) fn current_update_arch() -> &'static str {
    #[cfg(all(target_os = "windows", not(feature = "flutter")))]
    {
        "x86"
    }
    #[cfg(not(all(target_os = "windows", not(feature = "flutter"))))]
    {
        std::env::consts::ARCH
    }
}

pub(crate) fn current_update_format(update_msi: bool) -> &'static str {
    #[cfg(any(
        not(target_os = "windows"),
        all(target_os = "windows", not(feature = "flutter"))
    ))]
    let _ = update_msi;
    #[cfg(all(target_os = "windows", feature = "flutter"))]
    {
        if update_msi {
            return "msi";
        }
        "exe"
    }
    #[cfg(all(target_os = "windows", not(feature = "flutter")))]
    {
        "exe"
    }
    #[cfg(target_os = "macos")]
    {
        "dmg"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "unknown"
    }
}

pub fn current_update_artifact_query(update_msi: bool) -> UpdateArtifactQuery<'static> {
    UpdateArtifactQuery {
        platform: current_update_platform(),
        arch: current_update_arch(),
        format: current_update_format(update_msi),
    }
}

pub fn verified_update_artifact_for_release_page_url(
    release_page_url: &str,
    query: UpdateArtifactQuery<'_>,
) -> ResultType<VerifiedUpdateArtifact> {
    let artifact = verified_update_artifact_from_release_page_url(release_page_url, &query)?;
    *VERIFIED_UPDATE_ARTIFACT.lock().unwrap() = Some(artifact.clone());
    Ok(artifact)
}

pub fn verified_update_artifact_for_download_url(
    download_url: &str,
) -> ResultType<VerifiedUpdateArtifact> {
    VERIFIED_UPDATE_ARTIFACT
        .lock()
        .unwrap()
        .as_ref()
        .filter(|artifact| artifact.url == download_url)
        .cloned()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("update artifact was not verified"))
}

pub(super) fn verified_update_artifact_from_release_page_url(
    update_url: &str,
    query: &UpdateArtifactQuery<'_>,
) -> ResultType<VerifiedUpdateArtifact> {
    let release_id = release_id_from_update_url(update_url)?;
    let display_version = display_version_from_release_id(&release_id)?;
    let expected_artifact_url_prefix =
        format!("https://github.com/danielneagu2000/Rust-Desktop/releases/download/{release_id}/");
    // RDN Remote: this repository's releases carry update-manifest.json, written by
    // .github/workflows/publish-update.yml, instead of RustDesk-signed metadata.
    if let Ok(manifest) =
        fetch_update_sidecar_bytes(&format!("{expected_artifact_url_prefix}update-manifest.json"))
    {
        return artifact_from_update_manifest(
            &manifest,
            &release_id,
            &display_version,
            &expected_artifact_url_prefix,
            query,
        );
    }
    let metadata_url = format!("{expected_artifact_url_prefix}rustdesk-update.json");
    let signature_url = format!("{metadata_url}.sig");
    let metadata_bytes = fetch_update_sidecar_bytes(&metadata_url)?;
    let signature_bytes = fetch_update_sidecar_bytes(&signature_url)?;
    let requirements = UpdateMetadataRequirements {
        expected_version: display_version.as_str(),
        expected_release_id: release_id.as_str(),
        expected_artifact_url_prefix: expected_artifact_url_prefix.as_str(),
        artifact: *query,
    };
    crate::update_metadata::verify_update_metadata(&metadata_bytes, &signature_bytes, requirements)
}

/// The installer for `query` from an RDN release's update-manifest.json
/// ({"tag": ..., "files": {name: sha256}, "sizes": {name: bytes}}). Installers are named
/// rustdesk-<tag>-<arch>.<ext>, as the updaters up to 1.5.1-2 requested them.
fn artifact_from_update_manifest(
    manifest: &[u8],
    release_id: &str,
    version: &str,
    url_prefix: &str,
    query: &UpdateArtifactQuery<'_>,
) -> ResultType<VerifiedUpdateArtifact> {
    #[derive(serde_derive::Deserialize)]
    struct Manifest {
        tag: String,
        files: std::collections::HashMap<String, String>,
        #[serde(default)]
        sizes: std::collections::HashMap<String, u64>,
    }
    let manifest: Manifest = serde_json::from_slice(manifest)?;
    if manifest.tag != release_id {
        bail!("update-manifest.json is for {}, not {}", manifest.tag, release_id);
    }
    let arch = if query.arch == "x86" { "x86-sciter" } else { query.arch };
    let file_name = format!("rustdesk-{release_id}-{arch}.{}", query.format);
    let Some(sha256) = manifest.files.get(&file_name) else {
        bail!("{} is not in update-manifest.json", file_name);
    };
    if sha256.len() != 64 || !sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("update-manifest.json has an invalid SHA-256 for {}", file_name);
    }
    let Some(&size) = manifest.sizes.get(&file_name).filter(|size| **size > 0) else {
        bail!("update-manifest.json has no size for {}", file_name);
    };
    Ok(VerifiedUpdateArtifact {
        version: version.to_owned(),
        url: format!("{url_prefix}{file_name}"),
        #[cfg(target_os = "macos")]
        file_name,
        size,
        sha256: sha256.clone(),
    })
}

fn fetch_update_sidecar_bytes(url: &str) -> ResultType<Vec<u8>> {
    let client = create_http_client_with_url_strict(url)?;
    let mut response = client
        .get(url)
        .timeout(UPDATE_SIDECAR_HTTP_REQUEST_TIMEOUT)
        .send()?;
    if !response.status().is_success() {
        bail!(
            "Failed to download update metadata sidecar: {}",
            response.status()
        );
    }
    read_limited_response_bytes(
        &mut response,
        UPDATE_METADATA_SIDECAR_MAX_BYTES,
        "Update metadata sidecar",
    )
}

fn read_limited_response_bytes<R: Read>(
    reader: &mut R,
    limit: u64,
    what: &str,
) -> ResultType<Vec<u8>> {
    let mut limited_reader = reader.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    limited_reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("{what} exceeds maximum allowed size of {limit} bytes");
    }
    Ok(bytes)
}

pub fn get_update_download_file_from_url(url: &str) -> Option<PathBuf> {
    let parsed = url::Url::parse(url).ok()?;
    // Check the raw prefix before Url normalizes default ports.
    if !url.starts_with("https://github.com/")
        || parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }

    let mut segments = parsed.path_segments()?;
    let owner = segments.next()?;
    let repo = segments.next()?;
    let releases = segments.next()?;
    let download = segments.next()?;
    let tag = segments.next()?;
    let filename = segments.next()?;

    if owner != "danielneagu2000"
        || repo != "Rust-Desktop"
        || releases != "releases"
        || download != "download"
        || tag.is_empty()
        || segments.next().is_some()
        || !is_plain_update_filename(filename)
    {
        return None;
    }

    Some(std::env::temp_dir().join(filename))
}

fn is_plain_update_filename(filename: &str) -> bool {
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains(':')
    {
        return false;
    }

    let mut components = Path::new(filename).components();
    matches!(
        components.next(),
        Some(Component::Normal(name)) if name.to_str() == Some(filename)
    ) && components.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdn_update_manifest_selects_the_installer() {
        let sha = "ab".repeat(32);
        let manifest = format!(
            r#"{{"tag": "1.5.1-3", "base": "1.5.1",
                "files": {{"rustdesk-1.5.1-3-x86_64.exe": "{sha}", "rustdesk-1.5.1-3-x86-sciter.exe": "{sha}"}},
                "sizes": {{"rustdesk-1.5.1-3-x86_64.exe": 1234, "rustdesk-1.5.1-3-x86-sciter.exe": 99}}}}"#
        );
        let prefix = "https://github.com/rustdesk/rustdesk/releases/download/1.5.1-3/";
        let query = |arch, format| UpdateArtifactQuery { platform: "windows", arch, format };
        let artifact = artifact_from_update_manifest(
            manifest.as_bytes(), "1.5.1-3", "1.5.1-3", prefix, &query("x86_64", "exe"),
        )
        .unwrap();
        assert_eq!(artifact.url, format!("{prefix}rustdesk-1.5.1-3-x86_64.exe"));
        assert_eq!((artifact.size, artifact.sha256.as_str()), (1234, sha.as_str()));
        let sciter = artifact_from_update_manifest(
            manifest.as_bytes(), "1.5.1-3", "1.5.1-3", prefix, &query("x86", "exe"),
        )
        .unwrap();
        assert_eq!(sciter.size, 99);
        // Another release's manifest, an installer it does not list, or one without a size.
        for (release_id, format) in [("1.5.1-4", "exe"), ("1.5.1-3", "msi")] {
            assert!(artifact_from_update_manifest(
                manifest.as_bytes(), release_id, release_id, prefix, &query("x86_64", format),
            )
            .is_err());
        }
        let no_sizes = manifest.replace("\"sizes\"", "\"other\"");
        assert!(artifact_from_update_manifest(
            no_sizes.as_bytes(), "1.5.1-3", "1.5.1-3", prefix, &query("x86_64", "exe"),
        )
        .is_err());
    }

    #[test]
    fn update_download_file_accepts_expected_github_asset_urls() {
        let file = get_update_download_file_from_url(
            "https://github.com/danielneagu2000/Rust-Desktop/releases/download/1.4.0/rustdesk-1.4.0-x86_64.dmg",
        )
        .expect("valid GitHub release asset URL");

        assert_eq!(
            file.file_name().and_then(|name| name.to_str()),
            Some("rustdesk-1.4.0-x86_64.dmg")
        );
    }

    #[test]
    fn update_download_file_rejects_untrusted_or_malformed_urls() {
        for url in [
            "http://github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe",
            "https://example.com/rustdesk.exe",
            "https://github.com/other/project/releases/download/1/rustdesk.exe",
            "https://github.com/rustdesk/rustdesk/releases/download/1/",
            "https://github.com/rustdesk/rustdesk/releases/download/1/nested/rustdesk.exe",
            "https://github.com/rustdesk/rustdesk/releases/download/1/C:rustdesk.exe",
            "https://user@github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe",
            "https://github.com:443/rustdesk/rustdesk/releases/download/1/rustdesk.exe",
            "https://github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe?download=1",
            "https://github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe#download",
            "not a url",
        ] {
            assert!(get_update_download_file_from_url(url).is_none(), "{url}");
        }
    }
}
