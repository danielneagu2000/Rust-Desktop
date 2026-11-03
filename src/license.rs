//! Device licenses issued by the self-hosted security panel (server/panel).
//!
//! The panel signs a short-lived token with the rendezvous server's key, so the client
//! verifies it offline with the `RS_PUB_KEY` it is built with. The token binds the
//! license to this machine's uuid and carries an expiry; the panel refreshes it in the
//! heartbeat response and sends an empty token once the license is revoked or expired.
//! When `REQUIRED` is false (unbranded builds) nothing here has any effect.

use base::message_proto::{message, LoginRequest, Message};
use hbb_common::{
    config::Config, log, protobuf::Message as _, sodiumoxide::crypto::sign, tokio, ResultType,
};
use serde::Deserialize;
use std::time::{Duration, Instant};

/// Set by branding/apply.py (LICENSE_REQUIRED in branding/brand.env).
pub const REQUIRED: bool = true;
pub const OPTION_TOKEN: &str = "license-token";
/// Leading bytes of every signed token (server/panel/panel.py TOKEN_PREFIX). The server key
/// also signs hbbs' protobuf messages; a zero first byte can never start one of those.
const TOKEN_PREFIX: &[u8] = b"\x00RDN-LICENSE-1\x00";
pub const BLOCKED_MSG: &str =
    "The RDN Remote license is missing or has expired. Activate a license code in the app.";

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
    /// 1 when the license allows a permanent password on this computer, set in the panel.
    #[serde(default)]
    w: u8,
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

/// Logins with the permanent password (server process). The panel turns it on per license, and
/// it is part of the signed token, so editing the local config can't turn it on.
pub fn permanent_password_allowed() -> bool {
    !REQUIRED || verify(&Config::get_option(OPTION_TOKEN)).map_or(false, |c| c.w == 1)
}

/// Outgoing connections (UI process, which sees the service's options over IPC).
pub fn check_outgoing() -> ResultType<()> {
    if REQUIRED && verify(&crate::ui_interface::get_option(OPTION_TOKEN)).is_none() {
        hbb_common::bail!(BLOCKED_MSG);
    }
    Ok(())
}

/// Pass the panel signs for every licensed device (issue_pass in server/panel/panel.py), sent
/// to the computers it controls as proof of its license. Peers see it, so it carries the
/// device ID, an expiry and whether it may control computers without a license, no uuid.
const PASS_PREFIX: &[u8] = b"\x00RDN-PASS-1\x00";
const OPTION_PASS: &str = "license-pass";
/// "Y" when the panel's require_controller_license is on (server process).
const OPTION_STRICT: &str = "license-strict";
pub const PEER_BLOCKED_MSG: &str = "The remote computer has no RDN Remote license, and your license does not allow controlling computers without one.";
pub const STRICT_BLOCKED_MSG: &str = "The remote computer only accepts connections from RDN Remote apps with a valid license. Update the app and check its license.";

#[derive(Deserialize)]
struct Pass {
    /// Device ID the pass was issued to.
    i: String,
    /// Expiry, unix seconds.
    e: i64,
    /// 1 when the license may control computers without a license.
    #[serde(default)]
    p: u8,
    /// The device key (base64) once the device's activation is bound to it; the app then signs
    /// each login with that key (`sign_login`), so a pass copied from a login is useless on its
    /// own. Empty in passes for apps before 1.5.1-4.
    #[serde(default)]
    k: String,
}

/// Leading bytes of what a controlling app signs for each login (`rdn_proof`).
const PROOF_PREFIX: &[u8] = b"\x00RDN-PROOF-1\x00";
/// "Y" when the panel's require_signed_apps is on: passes without a device key are refused.
const OPTION_PASS_KEY: &str = "license-pass-key";

/// The connection's challenge (sent by the controlled computer in `Hash`) and the ID the login
/// is for, so a signature seen by one computer is no use for logging in to another.
fn proof_message(lr: &LoginRequest, challenge: &str) -> Vec<u8> {
    [
        PROOF_PREFIX,
        challenge.as_bytes(),
        b"\0",
        lr.username.as_bytes(),
        b"\0",
        lr.my_id.as_bytes(),
        b"\0",
        lr.rdn_pass.as_bytes(),
    ]
    .concat()
}

/// A pass with a device key counts only with that key's signature of this login, made for this
/// computer: its ID, or an address when the controlling app dialed one.
fn proof_ok(pass: &Pass, lr: &LoginRequest, challenge: &str, own_id: &str) -> bool {
    if pass.k.is_empty() {
        return Config::get_option(OPTION_PASS_KEY) != "Y";
    }
    if lr.username != own_id && !lr.username.contains(['.', ':']) {
        return false;
    }
    let pk = crate::decode64(&pass.k)
        .ok()
        .and_then(|k| sign::PublicKey::from_slice(&k));
    let sig = sign::Signature::from_bytes(&lr.rdn_proof).ok();
    match (pk, sig) {
        (Some(pk), Some(sig)) => sign::verify_detached(&sig, &proof_message(lr, challenge), &pk),
        _ => false,
    }
}

/// Signs an outgoing login with this device's key (UI process), for passes that name it.
pub async fn sign_login(lr: &mut LoginRequest, challenge: &str) {
    if !REQUIRED || lr.rdn_pass.is_empty() {
        return;
    }
    match device_secret_key().await {
        Some(sk) => {
            lr.rdn_proof = sign::sign_detached(&proof_message(lr, challenge), &sk)
                .to_bytes()
                .to_vec()
                .into();
        }
        None => log::warn!("No device key to sign the login with"),
    }
}

/// `sign_login` for a login or for the login inside a switch-sides response.
pub async fn sign_login_msg(mut msg: Message, challenge: &str) -> Message {
    match msg.union.as_mut() {
        Some(message::Union::LoginRequest(lr)) => sign_login(lr, challenge).await,
        Some(message::Union::SwitchSidesResponse(s)) => {
            if let Some(lr) = s.lr.as_mut() {
                sign_login(lr, challenge).await;
            }
        }
        _ => {}
    }
    msg
}

/// The key this device registered at hbbs. The UI process asks the service for it, whose
/// config holds the key on desktop.
async fn device_secret_key() -> Option<sign::SecretKey> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let key_pair = Some(Config::get_key_pair());
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let key_pair = {
        let mut conn = crate::ipc::connect(1000, "").await.ok()?;
        conn.send(&crate::ipc::Data::ConfirmedKey(None))
            .await
            .ok()?;
        match conn.next_timeout(1000).await {
            Ok(Some(crate::ipc::Data::ConfirmedKey(key_pair))) => key_pair,
            _ => None,
        }
    };
    sign::SecretKey::from_slice(&key_pair?.0)
}

/// Leading bytes of what apps sign when they post to the license server (SIG_PREFIX in
/// server/panel/panel.py).
const REQUEST_PREFIX: &[u8] = b"\x00RDN-API-1\x00";

/// Header for `post_request` with the device key's signature of `body` posted to `path`, so the
/// panel can tell this computer from someone who only knows its uuid; empty without a key.
pub fn request_signature(path: &str, body: &str, secret_key: &[u8]) -> String {
    let Some(sk) = sign::SecretKey::from_slice(secret_key).filter(|_| REQUIRED) else {
        return String::new();
    };
    let msg = [REQUEST_PREFIX, path.as_bytes(), b"\0", body.as_bytes()].concat();
    let sig = sign::sign_detached(&msg, &sk);
    format!("X-RDN-Signature: {}", crate::encode64(sig.to_bytes()))
}

/// Unix seconds for the "ts" of a signed heartbeat, which the panel accepts for a limited time.
pub fn request_time() -> i64 {
    now()
}

/// Panel setting pushed in the heartbeat response (server process).
pub fn store_pass_key(on: bool) {
    let value = if on { "Y" } else { "" };
    if REQUIRED && Config::get_option(OPTION_PASS_KEY) != value {
        Config::set_option(OPTION_PASS_KEY.to_owned(), value.to_owned());
    }
}

fn verify_pass(pass: &str) -> Option<Pass> {
    if pass.is_empty() {
        return None;
    }
    let signed = crate::decode64(pass).ok()?;
    let pk = crate::common::get_rs_pk(hbb_common::config::RS_PUB_KEY)?;
    let payload = hbb_common::sodiumoxide::crypto::sign::verify(&signed, &pk).ok()?;
    let pass: Pass = serde_json::from_slice(payload.strip_prefix(PASS_PREFIX)?).ok()?;
    (pass.e > now()).then_some(pass)
}

/// Pass pushed by the panel in the heartbeat response (server process); empty without a valid
/// license.
pub fn store_pass(pass: &str) {
    if !REQUIRED || Config::get_option(OPTION_PASS) == pass {
        return;
    }
    if pass.is_empty() || verify_pass(pass).is_some() {
        Config::set_option(OPTION_PASS.to_owned(), pass.to_owned());
    } else {
        hbb_common::throttled_log!(
            crate::common::API_LOG_INTERVAL,
            warn,
            "Ignoring a license pass that does not verify"
        );
    }
}

/// Sent with every outgoing login (UI process).
pub fn login_pass() -> String {
    if !REQUIRED {
        return String::new();
    }
    crate::ui_interface::get_option(OPTION_PASS)
}

/// Panel setting pushed in the heartbeat response (server process).
pub fn store_strict(on: bool) {
    let value = if on { "Y" } else { "" };
    if REQUIRED && Config::get_option(OPTION_STRICT) != value {
        Config::set_option(OPTION_STRICT.to_owned(), value.to_owned());
    }
}

/// Incoming login (server process), with the pass the controlling app sent for the ID it logs
/// in with and its signature of this connection's challenge. A licensed computer accepts it, or
/// with the panel's require_controller_license on only when the pass is valid; one without a
/// license only when the pass allows that.
pub fn login_check(lr: &LoginRequest, challenge: &str) -> Result<(), &'static str> {
    let own_id = Config::get_id();
    let pass = verify_pass(&lr.rdn_pass)
        .filter(|p| p.i == lr.my_id && proof_ok(p, lr, challenge, &own_id));
    if is_allowed() {
        if Config::get_option(OPTION_STRICT) == "Y" && pass.is_none() {
            return Err(STRICT_BLOCKED_MSG);
        }
        return Ok(());
    }
    match pass {
        Some(p) if p.p == 1 => Ok(()),
        _ => Err(PEER_BLOCKED_MSG),
    }
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

/// JSON for the Flutter license banner and password settings:
/// {"required", "valid", "expires", "client", "permanent"}.
pub fn ui_status() -> String {
    let claims = verify(&crate::ui_interface::get_option(OPTION_TOKEN));
    serde_json::json!({
        "required": REQUIRED,
        "valid": claims.is_some(),
        "expires": claims.as_ref().map(|c| c.x).unwrap_or(0),
        "permanent": claims.as_ref().map_or(false, |c| c.w == 1),
        "client": claims.map(|c| c.n).unwrap_or_default(),
    })
    .to_string()
}

/// Activates `code` on the panel and stores the returned token; returns JSON
/// {"ok": true} or {"error": "..."} for the UI.
pub fn activate(code: &str) -> String {
    // ipc::get_id and ipc::set_options start their own Tokio runtime; called inside
    // activate_'s runtime they panic, and with panic = "abort" the app closes.
    let result = activate_(code.trim(), device_id())
        .map(|token| crate::ui_interface::set_option(OPTION_TOKEN.to_owned(), token));
    match result {
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

/// The language the app is shown in, so the license server can answer in it.
fn ui_lang() -> String {
    let lang = hbb_common::config::LocalConfig::get_option("lang");
    if !lang.is_empty() {
        return lang;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let locale = sys_locale::get_locale().unwrap_or_default();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let locale = String::new();
    locale
}

#[tokio::main(flavor = "current_thread")]
async fn activate_(code: &str, id: String) -> ResultType<String> {
    let api = crate::common::get_api_server(
        crate::ui_interface::get_option("api-server"),
        crate::ui_interface::get_option("custom-rendezvous-server"),
    );
    if api.is_empty() {
        hbb_common::bail!("The license server is not configured");
    }
    let body = serde_json::json!({
        "code": code,
        "uuid": crate::encode64(hbb_common::get_uuid()),
        "id": id,
        "hostname": crate::common::hostname(),
        "lang": ui_lang(),
    })
    .to_string();
    let header = match device_secret_key().await {
        Some(sk) => request_signature("/api/license/activate", &body, &sk.0),
        None => String::new(),
    };
    let resp = crate::post_request(format!("{api}/api/license/activate"), body, &header).await?;
    let v: serde_json::Value = serde_json::from_str(&resp)
        .map_err(|_| hbb_common::anyhow::anyhow!("Invalid response from the license server"))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        hbb_common::bail!("{err}");
    }
    let token = v.get("license").and_then(|t| t.as_str()).unwrap_or_default();
    if verify(token).is_none() {
        hbb_common::bail!("The license received is not valid for this computer");
    }
    Ok(token.to_owned())
}

/// Reason the panel gave with its last heartbeat "disconnect" (e.g. the license's limit
/// of simultaneous sessions); empty for a plain disconnect from the web console.
static DISCONNECT_REASON: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

pub fn set_disconnect_reason(reason: &str) {
    *DISCONNECT_REASON.lock().unwrap() = reason.chars().take(300).collect();
}

pub fn disconnect_reason() -> String {
    let reason = DISCONNECT_REASON.lock().unwrap().clone();
    if reason.is_empty() {
        "Closed manually by web console".to_owned()
    } else {
        reason
    }
}

/// Wrong-password lockout set in the panel: (attempts, minutes). (0, 0) keeps RustDesk's own rules.
static LOCKOUT: std::sync::Mutex<(i32, i32)> = std::sync::Mutex::new((0, 0));

pub fn set_lockout(v: Option<&serde_json::Value>) {
    let get = |i: usize| {
        v.and_then(|v| v.get(i))
            .and_then(|n| n.as_i64())
            .unwrap_or(0)
            .clamp(0, 10080) as i32
    };
    *LOCKOUT.lock().unwrap() = (get(0), get(1));
}

pub fn lockout() -> Option<(i32, i32)> {
    let (attempts, minutes) = *LOCKOUT.lock().unwrap();
    (attempts > 0 && minutes > 0).then_some((attempts, minutes))
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

/// When the computer's sending schedule ends. One schedule for all its connections, as the limit
/// is for the computer: parallel sessions and file transfers share it.
static NEXT_SEND: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);

/// Books `cost` of sending time at the end of the computer's schedule; returns how far from now
/// the booking ends.
fn reserve(cost: Duration) -> Duration {
    let now = Instant::now();
    let mut next = NEXT_SEND.lock().unwrap();
    let end = next.map_or(now, |n| n.max(now)) + cost;
    *next = Some(end);
    end.saturating_duration_since(now)
}

/// Paces what a connection sends (screen, sound, files) to the license's bandwidth limit.
/// Waiting before a send is what a slower link would do, so the video quality control
/// adapts to it the same way.
#[derive(Default)]
pub struct Throttle {
    kbps: u32,
    checked: Option<Instant>,
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
        let cost = Duration::from_secs_f64(bytes as f64 * 8.0 / (kbps as f64 * 1000.0));
        let ahead = reserve(cost);
        if ahead > Self::BURST {
            tokio::time::sleep(ahead - Self::BURST).await;
        }
    }

    fn limit(&mut self) -> u32 {
        if self.checked.map_or(true, |t| t.elapsed() >= Self::REFRESH) {
            self.kbps = bandwidth_kbps();
            self.checked = Some(Instant::now());
            if self.kbps == 0 {
                *NEXT_SEND.lock().unwrap() = None;
            }
        }
        self.kbps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(proof_key: Option<&sign::SecretKey>, challenge: &str) -> LoginRequest {
        let mut lr = LoginRequest {
            username: "111222333".to_owned(),
            my_id: "444555666".to_owned(),
            rdn_pass: "pass".to_owned(),
            ..Default::default()
        };
        if let Some(sk) = proof_key {
            lr.rdn_proof = sign::sign_detached(&proof_message(&lr, challenge), sk)
                .to_bytes()
                .to_vec()
                .into();
        }
        lr
    }

    fn pass_for(pk: &sign::PublicKey) -> Pass {
        Pass {
            i: "444555666".to_owned(),
            e: now() + 60,
            p: 0,
            k: crate::encode64(pk),
        }
    }

    #[test]
    fn a_pass_with_a_device_key_needs_that_key_on_this_login() {
        let (pk, sk) = sign::gen_keypair();
        let (_, other_sk) = sign::gen_keypair();
        let pass = pass_for(&pk);
        let signed = login(Some(&sk), "abc123");
        assert!(proof_ok(&pass, &signed, "abc123", "111222333"));
        // Copied from this login: another challenge, or another computer.
        assert!(!proof_ok(&pass, &signed, "xyz789", "111222333"));
        assert!(!proof_ok(&pass, &signed, "abc123", "999888777"));
        // Sent without a signature, or signed by someone else.
        let unsigned = login(None, "abc123");
        assert!(!proof_ok(&pass, &unsigned, "abc123", "111222333"));
        let other = login(Some(&other_sk), "abc123");
        assert!(!proof_ok(&pass, &other, "abc123", "111222333"));
        // Dialed by address: the address stands for the ID.
        let mut by_ip = login(None, "abc123");
        by_ip.username = "192.168.1.20:21118".to_owned();
        by_ip.rdn_proof = sign::sign_detached(&proof_message(&by_ip, "abc123"), &sk)
            .to_bytes()
            .to_vec()
            .into();
        assert!(proof_ok(&pass, &by_ip, "abc123", "111222333"));
    }

    #[test]
    fn signed_requests_verify_with_the_device_key() {
        let (pk, sk) = sign::gen_keypair();
        let header = request_signature("/api/heartbeat", "{\"a\":1}", &sk.0);
        let sig = header.strip_prefix("X-RDN-Signature: ").unwrap();
        let sig = sign::Signature::from_bytes(&crate::decode64(sig).unwrap()).unwrap();
        let msg = [REQUEST_PREFIX, b"/api/heartbeat", b"\0", b"{\"a\":1}"].concat();
        assert!(sign::verify_detached(&sig, &msg, &pk));
        assert!(request_signature("/api/heartbeat", "{}", b"short").is_empty());
    }

    #[tokio::test]
    async fn parallel_connections_share_the_computer_limit() {
        // 8 kbit/s = 1000 bytes/s: 400 bytes take 0.4 s, of which a connection on its own waits
        // 0.4 s - BURST = 0.2 s. Sharing the schedule, the second waits behind the first: 0.4 s.
        let throttle = || Throttle {
            kbps: 8,
            checked: Some(Instant::now()),
        };
        let (mut a, mut b) = (throttle(), throttle());
        a.wait(400).await;
        let started = Instant::now();
        b.wait(400).await;
        assert!(started.elapsed() >= Duration::from_millis(350));
    }
}
