//! Device licenses issued by the self-hosted security panel (server/panel).
//!
//! The panel signs a short-lived token with the rendezvous server's key, so the client
//! verifies it offline with the `RS_PUB_KEY` it is built with. The token binds the
//! license to this machine's uuid and carries an expiry; the panel refreshes it in the
//! heartbeat response and sends an empty token once the license is revoked or expired.
//! When `REQUIRED` is false (unbranded builds) nothing here has any effect.

use hbb_common::{config::Config, log, tokio, ResultType};
use serde::Deserialize;

/// Set by branding/apply.py (LICENSE_REQUIRED in branding/brand.env).
pub const REQUIRED: bool = true;
pub const OPTION_TOKEN: &str = "license-token";
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
    let claims: Claims = serde_json::from_slice(&payload).ok()?;
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
        "id": crate::ui_interface::get_id(),
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
