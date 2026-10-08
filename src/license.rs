//! Device licenses issued by the self-hosted security panel (server/panel).
//!
//! The panel signs a short-lived token with the rendezvous server's key, so the client
//! verifies it offline with the `RS_PUB_KEY` it is built with. The token binds the
//! license to this machine's uuid and carries an expiry; the panel refreshes it in the
//! heartbeat response and sends an empty token once the license is revoked or expired.
//! When `REQUIRED` is false (unbranded builds) nothing here has any effect.

use base::message_proto::Message;
use hbb_common::{config::Config, log, protobuf::Message as _, tokio, ResultType};
use serde::Deserialize;
use std::time::{Duration, Instant};

/// Set by branding/apply.py (LICENSE_REQUIRED in branding/brand.env).
pub const REQUIRED: bool = true;
pub const OPTION_TOKEN: &str = "license-token";
/// Leading bytes of every signed token (server/panel/panel.py TOKEN_PREFIX). The server key
/// also signs hbbs' protobuf messages; a zero first byte can never start one of those.
const TOKEN_PREFIX: &[u8] = b"\x00RDN-LICENSE-1\x00";
pub const BLOCKED_MSG: &str =
    "Licența RDN Remote lipsește sau a expirat. Activează un cod de licență în aplicație.";

#[derive(Deserialize)]
struct Claims {
    /// Machine uuid (base64), as sent in the heartbeat.
    u: String,
    /// Token expiry, unix seconds.
    e: i64,
    /// License expiry, unix seconds; 0 for unlimited.
    #[serde(default)]
    x: i64,
    /// Client the license was issued to.
    #[serde(default)]
    n: String,
    /// Upload limit for this computer in kbit/s, set per license in the panel; 0 = none.
    #[serde(default)]
    b: u32,
}

fn now() -> i64 {
    hbb_common::get_time() / 1000
}

fn verify(token: &str) -> Option<Claims> {
    if token.is_empty() {
        return None;
    }
    let signed = crate::decode64(token).ok()?;
    let pk = crate::common::get_rs_pk(hbb_common::config::RS_PUB_KEY)?;
    let payload = hbb_common::sodiumoxide::crypto::sign::verify(&signed, &pk).ok()?;
    let claims: Claims = serde_json::from_slice(payload.strip_prefix(TOKEN_PREFIX)?).ok()?;
    if claims.u != crate::encode64(hbb_common::get_uuid()) || claims.e <= now() {
        return None;
    }
    Some(claims)
}

/// Incoming connections (server process).
pub fn is_allowed() -> bool {
    !REQUIRED || verify(&Config::get_option(OPTION_TOKEN)).is_some()
}

/// Outgoing connections (UI process, which sees the service's options over IPC).
pub fn check_outgoing() -> ResultType<()> {
    if REQUIRED && verify(&crate::ui_interface::get_option(OPTION_TOKEN)).is_none() {
        hbb_common::bail!(BLOCKED_MSG);
    }
    Ok(())
}

/// Token pushed by the panel in the heartbeat response (server process).
pub fn store_from_server(token: &str) {
    if !REQUIRED || Config::get_option(OPTION_TOKEN) == token {
        return;
    }
    if token.is_empty() || verify(token).is_some() {
        Config::set_option(OPTION_TOKEN.to_owned(), token.to_owned());
    } else {
        log::warn!("Ignoring a license token that does not verify");
    }
}

/// JSON for the Flutter license banner: {"required", "valid", "expires", "client"}.
pub fn ui_status() -> String {
    let claims = verify(&crate::ui_interface::get_option(OPTION_TOKEN));
    serde_json::json!({
        "required": REQUIRED,
        "valid": claims.is_some(),
        "expires": claims.as_ref().map(|c| c.x).unwrap_or(0),
        "client": claims.map(|c| c.n).unwrap_or_default(),
    })
    .to_string()
}

/// Activates `code` on the panel and stores the returned token; returns JSON
/// {"ok": true} or {"error": "..."} for the UI.
pub fn activate(code: &str) -> String {
    match activate_(code.trim()) {
        Ok(()) => serde_json::json!({ "ok": true }).to_string(),
        Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
    }
}

/// The ID shown in the app; ui_interface::get_id only exists in Flutter builds.
fn device_id() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::get_id();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return crate::ipc::get_id();
}

#[tokio::main(flavor = "current_thread")]
async fn activate_(code: &str) -> ResultType<()> {
    let api = crate::common::get_api_server(
        crate::ui_interface::get_option("api-server"),
        crate::ui_interface::get_option("custom-rendezvous-server"),
    );
    if api.is_empty() {
        hbb_common::bail!("Serverul de licențe nu este configurat");
    }
    let body = serde_json::json!({
        "code": code,
        "uuid": crate::encode64(hbb_common::get_uuid()),
        "id": device_id(),
        "hostname": crate::common::hostname(),
    });
    let resp = crate::post_request(format!("{api}/api/license/activate"), body.to_string(), "")
        .await?;
    let v: serde_json::Value = serde_json::from_str(&resp)
        .map_err(|_| hbb_common::anyhow::anyhow!("Răspuns invalid de la serverul de licențe"))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        hbb_common::bail!("{err}");
    }
    let token = v.get("license").and_then(|t| t.as_str()).unwrap_or_default();
    if verify(token).is_none() {
        hbb_common::bail!("Licența primită nu este validă pentru acest calculator");
    }
    crate::ui_interface::set_option(OPTION_TOKEN.to_owned(), token.to_owned());
    Ok(())
}

/// Upper bound of one file transfer block (BUF_SIZE in base::fs), charged per block sent.
pub const FILE_BLOCK: usize = 128 * 1024;

/// Outgoing limit (kbit/s) from this computer's license; 0 = unlimited.
fn bandwidth_kbps() -> u32 {
    if !REQUIRED {
        return 0;
    }
    verify(&Config::get_option(OPTION_TOKEN))
        .map(|c| c.b)
        .unwrap_or(0)
}

/// Paces what a connection sends (screen, sound, files) to the license's bandwidth limit.
/// Waiting before a send is what a slower link would do, so the video quality control
/// adapts to it the same way.
#[derive(Default)]
pub struct Throttle {
    kbps: u32,
    checked: Option<Instant>,
    next: Option<Instant>,
}

impl Throttle {
    const REFRESH: Duration = Duration::from_secs(10);
    const BURST: Duration = Duration::from_millis(200);

    pub async fn wait_msg(&mut self, msg: &Message) {
        if self.limit() > 0 {
            self.wait(msg.compute_size() as usize).await;
        }
    }

    pub async fn wait(&mut self, bytes: usize) {
        let kbps = self.limit();
        if kbps == 0 {
            return;
        }
        let now = Instant::now();
        let cost = Duration::from_secs_f64(bytes as f64 * 8.0 / (kbps as f64 * 1000.0));
        let next = self.next.map_or(now, |n| n.max(now)) + cost;
        self.next = Some(next);
        let ahead = next.saturating_duration_since(now);
        if ahead > Self::BURST {
            tokio::time::sleep(ahead - Self::BURST).await;
        }
    }

    fn limit(&mut self) -> u32 {
        if self.checked.map_or(true, |t| t.elapsed() >= Self::REFRESH) {
            self.kbps = bandwidth_kbps();
            self.checked = Some(Instant::now());
            if self.kbps == 0 {
                self.next = None;
            }
        }
        self.kbps
    }
}
