//! Sessions, the local emergency password, GitHub single sign-on, and the
//! second factor both sign-in paths pass through when it is enabled.
//!
//! GitHub is the primary sign-in path. The local password exists so that a
//! broken OAuth app or an unreachable github.com cannot lock the owner out.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::api::{answer, fail};
use crate::{totp, App, Shown};

pub const COOKIE: &str = "monitor_session";
/// The cookie a checked password leaves behind while the code is still owed.
pub const CHALLENGE_COOKIE: &str = "monitor_totp";
const STATE_COOKIE: &str = "monitor_oauth_state";
const SESSION_DAYS: i64 = 14;
/// Failed password attempts allowed per address before it is shut out.
const MAX_ATTEMPTS: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(900);
/// How long a half-finished sign-in may wait for its code. One step is 30
/// seconds, so five minutes covers a phone being fetched rather than a session.
const CHALLENGE_SECS: i64 = 300;
/// Codes one challenge accepts before it is spent.
///
/// Six digits in a 90-second window leave three valid codes; without this an
/// address with a stolen password could walk the whole space from one
/// challenge, and the per-address lockout below does not bound the number of
/// addresses behind a botnet. Five is what a mistyped pair of codes costs, and
/// it stays well below the ~333,000 guesses a 1-in-a-million chance needs.
const MAX_CODE_ATTEMPTS: u32 = 5;

/// How many password checks may run concurrently.
///
/// argon2 is deliberately expensive: one attempt costs 19 MiB and a tenth of a
/// core-second. Unbounded, that cost becomes a lever rather than a defence --
/// the lockout below bounds attempts per address, but nothing bounds the number
/// of addresses, which on IPv6 is a /64 the caller already controls.
///
/// Fixed at one: any limit at or above what the machine can run concurrently is
/// no limit at all. argon2 saturates a core, so a gate of four on a three-core
/// hub never reached four in flight and admitted a flood untouched -- 570 MB
/// against a unit file allowing 256. At one, 633 of 640 attempts are refused.
/// Deriving it from the core count would reopen the hole on smaller machines.
///
/// Refused rather than queued: a queue admits the same flood, merely later. The
/// cost is that two simultaneous sign-ins require one to retry.
const PASSWORD_CHECKS: usize = 1;
static PASSWORD_GATE: Semaphore = Semaphore::const_new(PASSWORD_CHECKS);

/// Serializes the tests that drive a password check.
///
/// [`PASSWORD_GATE`] is process-wide, so a test signing in while another holds
/// the one permit sees the same refusal a flood does -- and the test written
/// around that gate asserts on the permit it cannot get. Every test that calls
/// [`login`] takes this first.
#[cfg(test)]
pub(crate) static PASSWORD_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn random_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt =
        SaltString::encode_b64(&rand::random::<[u8; 16]>()).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?
        .to_string())
}

fn verify_password(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

/// Per-address failure counter. The hub keeps two: one for the sign-in page,
/// one for agent registration (`App::registrations`).
pub struct Throttle {
    seen: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// How long a failure is remembered. A field rather than the constant so
    /// tests can observe a lockout expire without sleeping for 15 minutes.
    window: Duration,
}

impl Default for Throttle {
    fn default() -> Self {
        Self { seen: Mutex::default(), window: LOCKOUT }
    }
}

impl Throttle {
    /// An IPv6 visitor holds a whole /64, so the full address as key would be a
    /// fresh bucket per attempt.
    fn key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & (!0u128 << 64)).into()),
            v4 => v4,
        }
    }

    pub(crate) fn locked(&self, ip: IpAddr) -> bool {
        let ip = Self::key(ip);
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&ip) {
            Some((n, since)) if since.elapsed() < self.window => *n >= MAX_ATTEMPTS,
            Some(_) => {
                map.remove(&ip);
                false
            }
            None => false,
        }
    }

    pub(crate) fn record_failure(&self, ip: IpAddr) {
        let ip = Self::key(ip);
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Addresses past their window are dropped here rather than allowed to
        // accumulate, which also restarts the count for a returning address.
        map.retain(|_, (_, since)| since.elapsed() < self.window);
        map.entry(ip).or_insert((0, Instant::now())).0 += 1;
    }

    pub(crate) fn clear(&self, ip: IpAddr) {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).remove(&Self::key(ip));
    }
}

/// Half-finished sign-ins: a password or a GitHub callback that still owes a
/// code, each holding the attempts it has left.
///
/// In memory rather than in `session`, where a row is what `session_valid`
/// accepts: a challenge that shared that table would be one predicate away from
/// being a session, and it deliberately is not one. A restart drops the
/// challenges with it, which costs whoever was mid-sign-in one retry.
#[derive(Default)]
pub struct Challenges {
    /// Token digest to (expiry, attempts used).
    seen: Mutex<HashMap<String, (i64, u32)>>,
}

impl Challenges {
    fn issue(&self, token_hash: String, expires_at: i64) {
        let now = Utc::now().timestamp();
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Spent challenges for other visitors are dropped here: nothing sweeps
        // this map, and an abandoned sign-in is the common case.
        map.retain(|_, (expiry, _)| *expiry > now);
        map.insert(token_hash, (expires_at, 0));
    }

    /// Attempts this challenge has left, or `None` when it is unknown, expired
    /// or spent.
    fn attempts_left(&self, token_hash: &str, now: i64) -> Option<u32> {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(token_hash) {
            Some((expiry, used)) if *expiry > now => Some(MAX_CODE_ATTEMPTS.saturating_sub(*used)),
            Some(_) => {
                map.remove(token_hash);
                None
            }
            None => None,
        }
    }

    /// Books one failed attempt against a challenge, reporting how many are now
    /// used. The challenge is dropped once they run out, so the caller cannot
    /// keep guessing from the same cookie.
    ///
    /// A challenge that is not there is reported as spent rather than created:
    /// `entry().or_insert()` here would resurrect one that another request had
    /// just used up or a successful sign-in had cleared, extending the cookie's
    /// life past its five attempts and letting it mint a second session.
    fn record_failure(&self, token_hash: &str, now: i64) -> u32 {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (expiry, _)| *expiry > now);
        let used = match map.get_mut(token_hash) {
            Some((expiry, used)) if *expiry > now => {
                *used += 1;
                *used
            }
            _ => return MAX_CODE_ATTEMPTS,
        };
        if used >= MAX_CODE_ATTEMPTS {
            map.remove(token_hash);
        }
        used
    }

    fn clear(&self, token_hash: &str) {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).remove(token_hash);
    }
}

/// Whether this hub asks for a code after the password. Both halves have to be
/// there: a secret with the switch off is an enrollment nobody confirmed, and
/// the switch with no secret is a hub that would demand a code nothing can
/// produce.
pub fn totp_enabled(app: &App) -> bool {
    app.db.get("totp_enabled").as_deref() == Some("on") && totp_secret(app).is_some()
}

/// The stored secret, empty ones reading as absent.
pub fn totp_secret(app: &App) -> Option<String> {
    app.db.get("totp_secret").filter(|s| !s.is_empty())
}

/// Serializes every claim on a one-time credential.
///
/// Both claims below are a read, a decision and a write, and the SQLite handle
/// is released between the two accesses. Two sign-ins arriving together would
/// otherwise both read the same row and each write back its own answer: with
/// recovery codes, the second write restores the code the first one spent, and
/// the same code present twice mints two sessions. One lock for both claims
/// rather than one each, since they are alternatives read from the same store.
static CLAIM: Mutex<()> = Mutex::new(());

/// Whether `code` is the authenticator's code, spending it so the same six
/// digits cannot be presented again inside their window.
///
/// The step is remembered rather than the code: a shown code is valid for one
/// step either side of now, which is exactly the window an attacker who read it
/// over a shoulder has to reuse it.
pub fn claim_code(app: &App, code: &str) -> bool {
    let _claim = CLAIM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(secret) = totp_secret(app) else { return false };
    let Some(step) = totp::verify_step(&secret, code, Utc::now().timestamp() as u64) else {
        return false;
    };
    let spent = app.db.get("totp_step").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    if step <= spent {
        return false;
    }
    // A failed write leaves the code unspent rather than the caller signed in.
    app.db.set("totp_step", &step.to_string()).is_ok()
}

/// Whether `code` is one of the unused recovery codes, consuming it. Stored as
/// digests, so a database read does not hand out a way in.
pub fn claim_recovery_code(app: &App, code: &str) -> bool {
    let _claim = CLAIM.lock().unwrap_or_else(|e| e.into_inner());
    let stored = app.db.get("totp_recovery").unwrap_or_default();
    let mut codes: Vec<String> = serde_json::from_str(&stored).unwrap_or_default();
    let digest = totp::recovery_digest(code);
    let Some(position) = codes.iter().position(|c| c == &digest) else { return false };
    codes.remove(position);
    match serde_json::to_string(&codes) {
        Ok(rest) => app.db.set("totp_recovery", &rest).is_ok(),
        Err(_) => false,
    }
}

/// Recovery codes not yet used, for the panel's count.
pub fn recovery_left(app: &App) -> usize {
    let stored = app.db.get("totp_recovery").unwrap_or_default();
    serde_json::from_str::<Vec<String>>(&stored).map(|codes| codes.len()).unwrap_or(0)
}

/// Turns the second factor off, clearing every trace of it: a leftover secret
/// would leave a later enrollment confirming itself.
///
/// The switch goes first and its write is reported: it is the one key whose
/// failure would have the panel tell the operator the factor is off while the
/// hub still demands a code. A secret left behind is harmless by comparison --
/// [`totp_enabled`] reads it as absent while the switch is off.
pub fn forget_totp(app: &App) -> Result<()> {
    app.db.set("totp_enabled", "")?;
    for key in ["totp_secret", "totp_recovery", "totp_step", "totp_confirmed_at"] {
        app.db.set(key, "")?;
    }
    Ok(())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

/// True when the request carries a live session cookie.
pub fn authed(app: &App, headers: &HeaderMap) -> bool {
    cookie_value(headers, COOKIE).is_some_and(|token| app.db.session_valid(&sha256(&token)))
}

fn set_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Digest of the caller's own session, so a session list can mark it.
pub fn current_session(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, COOKIE).map(|token| sha256(&token))
}

/// When a session with this expiry was issued. `issue_session` sets the expiry
/// to the issue time plus `SESSION_DAYS`, so this is exact rather than an
/// estimate; the two move together.
pub fn issued_at(expires_at: i64) -> i64 {
    expires_at - SESSION_DAYS * 86_400
}

/// The request's headers decide the Secure flag when the hub has no `--site`;
/// see `App::secure_cookies`.
pub fn issue_session(app: &App, headers: &HeaderMap) -> Result<String> {
    let token = random_token();
    app.db.create_session(&sha256(&token), Utc::now().timestamp() + SESSION_DAYS * 86_400)?;
    Ok(set_cookie(COOKIE, &token, SESSION_DAYS * 86_400, app.secure_cookies(headers)))
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub password: String,
}

pub async fn login(
    State(app): State<crate::Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let ip = client_ip(&app, &headers, peer.ip());
    if app.throttle.locked(ip) {
        return answer(StatusCode::TOO_MANY_REQUESTS, "尝试次数过多，稍后再试");
    }
    // Held across the check below, which is its purpose.
    let Ok(_permit) = PASSWORD_GATE.try_acquire() else {
        return answer(StatusCode::TOO_MANY_REQUESTS, "尝试次数过多，稍后再试");
    };
    let Some(stored) = app.db.get("admin_password_hash") else {
        return answer(StatusCode::FORBIDDEN, "没有设置应急密码，无法用密码登录");
    };
    if !verify_password(&body.password, &stored) {
        app.throttle.record_failure(ip);
        return answer(StatusCode::UNAUTHORIZED, "密码错误");
    }
    // A correct password clears the count only when it completes the sign-in.
    // Clearing it here would hand the second factor to anyone who has the
    // password: 4 guesses, ask for a fresh challenge, 4 more, forever.
    if totp_enabled(&app) {
        return issue_challenge(&app, &headers, "应急密码", ip, serde_json::json!({"totp_required": true}));
    }
    app.throttle.clear(ip);
    match issue_session(&app, &headers) {
        Ok(cookie) => {
            crate::notify::signed_in(&app, "应急密码", ip);
            with_cookies(Json(serde_json::json!({"ok": true})), [cookie])
        }
        Err(e) => fail(e),
    }
}

/// The half-signed-in answer: no session, a challenge cookie, and whatever the
/// caller's own next step looks like.
fn issue_challenge(
    app: &App,
    headers: &HeaderMap,
    method: &str,
    ip: std::net::IpAddr,
    body: serde_json::Value,
) -> Response {
    info!("{method} sign-in from {ip} still owes a two-factor code");
    let token = random_token();
    app.challenges.issue(sha256(&token), Utc::now().timestamp() + CHALLENGE_SECS);
    with_cookies(
        Json(body),
        [set_cookie(CHALLENGE_COOKIE, &token, CHALLENGE_SECS, app.secure_cookies(headers))],
    )
}

/// The second step of a sign-in that owed a code.
///
/// The challenge cookie says which half-finished sign-in this is; the code is
/// checked against both the authenticator and the unused recovery codes.
pub async fn login_totp(
    State(app): State<crate::Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CodeBody>,
) -> Response {
    let ip = client_ip(&app, &headers, peer.ip());
    if app.throttle.locked(ip) {
        return answer(StatusCode::TOO_MANY_REQUESTS, "尝试次数过多，稍后再试");
    }
    let Some(token) = cookie_value(&headers, CHALLENGE_COOKIE) else {
        return answer(StatusCode::UNAUTHORIZED, "登录已过期，请重新输入密码");
    };
    let digest = sha256(&token);
    let now = Utc::now().timestamp();
    let Some(left) = app.challenges.attempts_left(&digest, now) else {
        return answer(StatusCode::UNAUTHORIZED, "登录已过期，请重新输入密码");
    };
    if body.code.trim().is_empty() {
        return answer(StatusCode::BAD_REQUEST, "请输入两步验证码");
    }
    if !claim_code(&app, &body.code) && !claim_recovery_code(&app, &body.code) {
        app.throttle.record_failure(ip);
        let used = app.challenges.record_failure(&digest, now);
        warn!("two-factor code refused for a sign-in from {ip} ({used} attempts used)");
        if used >= MAX_CODE_ATTEMPTS {
            return answer(StatusCode::TOO_MANY_REQUESTS, "验证码错误次数过多，请重新登录");
        }
        return answer(StatusCode::UNAUTHORIZED, format!("验证码错误，还可以试 {} 次", left - 1));
    }
    app.throttle.clear(ip);
    app.challenges.clear(&digest);
    match issue_session(&app, &headers) {
        Ok(cookie) => {
            crate::notify::signed_in(&app, "应急密码 + 两步验证", ip);
            with_cookies(
                Json(serde_json::json!({"ok": true})),
                [cookie, set_cookie(CHALLENGE_COOKIE, "", 0, app.secure_cookies(&headers))],
            )
        }
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct CodeBody {
    #[serde(default)]
    pub code: String,
}

pub async fn logout(State(app): State<crate::Shared>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_value(&headers, COOKIE) {
        let _ = app.db.drop_session(&sha256(&token));
    }
    // The challenge goes too: it is the other half of a sign-in this browser is
    // abandoning, and leaving it live would keep a cookie whose only use is a
    // route the visitor has just walked away from.
    with_cookies(
        Json(serde_json::json!({"ok": true})),
        [
            set_cookie(COOKIE, "", 0, app.secure_cookies(&headers)),
            set_cookie(CHALLENGE_COOKIE, "", 0, app.secure_cookies(&headers)),
        ],
    )
}

/// Step one of the OAuth exchange: issue a state nonce and redirect the browser
/// to GitHub. The nonce returns in step two and must match.
pub async fn github_start(State(app): State<crate::Shared>, headers: HeaderMap) -> Response {
    let Some(client_id) = app.db.get("github_client_id").filter(|v| !v.is_empty()) else {
        return answer(StatusCode::PRECONDITION_FAILED, "没有配置 GitHub 登录");
    };
    let state = random_token();
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={client_id}&scope=read:user&state={state}"
    );
    with_cookies(Redirect::to(&url), [set_cookie(STATE_COOKIE, &state, 600, app.secure_cookies(&headers))])
}

/// Every field is optional. With required fields axum would reject a malformed
/// callback before the handler runs, returning a bare 400 and logging nothing;
/// GitHub also reports a refusal with `error` and no `code`.
#[derive(Deserialize, Default)]
pub struct Callback {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

pub async fn github_callback(
    State(app): State<crate::Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    // GitHub reports a refusal in the query string rather than the body.
    if let Some(error) = &query.error {
        let reason = query.error_description.as_deref().unwrap_or(error);
        let shown = if error == "access_denied" {
            "在 GitHub 上取消了授权"
        } else {
            "GitHub 拒绝了这次登录，原因见 hub 日志"
        };
        return sign_in_failed(
            &app,
            &headers,
            anyhow!("GitHub returned {error}: {reason}").context(Shown(shown.into())),
        );
    }
    // Reject a callback the browser did not initiate.
    let state = query.state.as_deref().unwrap_or_default();
    if state.is_empty() || cookie_value(&headers, STATE_COOKIE).as_deref() != Some(state) {
        return sign_in_failed(&app, &headers, anyhow!(Shown("登录已过期，请从登录页重新开始".into())));
    }
    let Some(code) = query.code.as_deref().filter(|c| !c.is_empty()) else {
        return sign_in_failed(&app, &headers, anyhow!(Shown("GitHub 没有返回授权码，请重新登录".into())));
    };
    let user = match github_login(&app, code).await {
        Ok(user) => user,
        Err(e) => return sign_in_failed(&app, &headers, e),
    };
    let ip = client_ip(&app, &headers, peer.ip());
    // GitHub proves who the visitor is, not that they hold the second factor:
    // the panel behind this redirect is the same one the password opens, so a
    // stolen GitHub session must not be enough either.
    if totp_enabled(&app) {
        let token = random_token();
        app.challenges.issue(sha256(&token), Utc::now().timestamp() + CHALLENGE_SECS);
        info!("GitHub {user} sign-in from {ip} still owes a two-factor code");
        // The code step lives on the sign-in page, which is what an unauthed
        // visitor is shown for any panel route.
        return with_cookies(
            Redirect::to("/admin/nodes?totp=1"),
            [
                clear_state(&app, &headers),
                set_cookie(CHALLENGE_COOKIE, &token, CHALLENGE_SECS, app.secure_cookies(&headers)),
            ],
        );
    }
    let session = match issue_session(&app, &headers) {
        Ok(cookie) => cookie,
        Err(e) => return sign_in_failed(&app, &headers, e),
    };
    crate::notify::signed_in(&app, &format!("GitHub {user}"), ip);
    with_cookies(Redirect::to("/admin/nodes"), [clear_state(&app, &headers), session])
}

/// Redirects the browser back to the sign-in page with the reason, rather than
/// leaving a bare 401 at a callback URL offering no way forward. The reason is
/// the error's [`Shown`] message, the same rule `api::fail` applies.
fn sign_in_failed(app: &App, headers: &HeaderMap, e: anyhow::Error) -> Response {
    // A rejected sign-in must leave a server-side record; the browser sees only
    // the redirect.
    warn!("GitHub sign-in rejected: {e:#}");
    let reason = e.downcast_ref::<Shown>().map_or(crate::api::INTERNAL, |shown| shown.0.as_str());
    let target = format!("/admin/nodes?login_error={}", urlencode(reason));
    with_cookies(Redirect::to(&target), [clear_state(app, headers), String::new()])
}

fn clear_state(app: &App, headers: &HeaderMap) -> String {
    set_cookie(STATE_COOKIE, "", 0, app.secure_cookies(headers))
}

/// Attaches several `Set-Cookie` headers to one response. An array of header
/// tuples is unsuitable: axum applies those with `HeaderMap::insert`, so a
/// second `Set-Cookie` replaces the first. Empty entries are skipped.
pub fn with_cookies<const N: usize>(response: impl IntoResponse, cookies: [String; N]) -> Response {
    let mut response = response.into_response();
    for cookie in cookies {
        if cookie.is_empty() {
            continue;
        }
        match cookie.parse() {
            Ok(value) => {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            Err(e) => return fail(e),
        }
    }
    response
}

/// Percent-encodes everything outside the unreserved set, sufficient for
/// placing an arbitrary message in a query string.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// What a sign-in says when a request to GitHub fails: unanswered is the hub's
/// network, an answer that does not decode is GitHub's.
fn github_failed(e: reqwest::Error) -> anyhow::Error {
    let shown = if e.is_decode() {
        "GitHub 的回复无法识别，稍后重新登录"
    } else {
        "hub 连不上 GitHub，检查它的网络后重新登录"
    };
    anyhow::Error::from(e).context(Shown(shown.into()))
}

/// Exchanges the code for a token and checks the login against the allow list,
/// returning the accepted login.
async fn github_login(app: &App, code: &str) -> Result<String> {
    let (Some(id), Some(secret)) = (app.db.get("github_client_id"), app.db.get("github_client_secret"))
    else {
        refuse!("没有配置 GitHub 登录");
    };
    let allowed = app.db.get("github_allowed_users").unwrap_or_default();
    let allowed: Vec<String> =
        allowed.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect();
    if allowed.is_empty() {
        // Without an allow list, any GitHub account could sign in.
        refuse!("没有设置允许登录的 GitHub 用户");
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        error_description: Option<String>,
    }
    let token: TokenResponse = app
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .json(&serde_json::json!({"client_id": id, "client_secret": secret, "code": code}))
        .send()
        .await
        .map_err(github_failed)?
        .json()
        .await
        .map_err(github_failed)?;
    let Some(access) = token.access_token else {
        // Typically an expired code, or a client secret that no longer matches.
        let reason = token.error_description.unwrap_or_else(|| "no access token".into());
        return Err(anyhow!(reason)
            .context(Shown("GitHub 没有发放令牌，检查 Client Secret 是否正确后重新登录".into())));
    };

    #[derive(Deserialize)]
    struct GithubUser {
        login: String,
    }
    let response = app
        .http
        .get("https://api.github.com/user")
        .header(header::AUTHORIZATION, format!("Bearer {access}"))
        .header(header::USER_AGENT, "monitor-hub")
        .send()
        .await
        .map_err(github_failed)?;
    let status = response.status();
    let body = response.text().await.map_err(github_failed)?;
    // Decoding an error page into GithubUser would report "missing field login"
    // instead of GitHub's actual message.
    let user: GithubUser = serde_json::from_str(&body)
        .with_context(|| format!("user response ({status}): {}", body.chars().take(200).collect::<String>()))
        .context(Shown(format!("GitHub 没有返回用户信息（HTTP {}），重新登录再试", status.as_u16())))?;

    if !allowed.contains(&user.login.to_lowercase()) {
        // The list stays in the log and out of the reason, which travels back in
        // a query string: any GitHub account can reach that page, and a reason
        // carrying the allow list would disclose the accounts worth phishing.
        warn!("GitHub user {} is not on the allowed list {allowed:?}", user.login);
        refuse!("GitHub 用户 {} 不在允许登录的名单里", user.login);
    }
    info!("GitHub sign-in accepted for {}", user.login);
    Ok(user.login)
}

/// Peer address, or the last hop in X-Forwarded-For when the request arrived
/// through a local reverse proxy. Used for throttling and the sign-in
/// notification, never for authorization.
///
/// The header is honoured only when the peer is itself local. Otherwise a
/// caller could mint a fresh identity per request, bypassing the lockout and
/// growing the throttle map without bound.
///
/// The last value is taken, not the first. Both documented proxies append
/// rather than replace -- nginx's `$proxy_add_x_forwarded_for`, caddy's
/// `reverse_proxy` default -- so a caller supplying its own `X-Forwarded-For`
/// leaves that value at the head while the address the proxy observed lands at
/// the tail. Reading the head would return control of the lockout to the
/// caller: rotating the header makes every attempt a fresh address, and writing
/// the operator's address locks them out of the sign-in page.
///
/// A second trusted proxy in front of the local one places its own address at
/// the tail instead. No single value in this header identifies the client, so
/// such a deployment must have its edge write the client address.
///
/// With `origin_cdn_only` on, the operator states that nothing but a CDN or
/// tunnel can reach the hub, and the peer no longer matters: the visitor is
/// `CF-Connecting-IP`, which Cloudflare overwrites, else the rightmost public
/// address in `X-Forwarded-For`, past any private hops a local proxy appended.
/// Rightmost, because a CDN appends what it saw and everything before that is
/// the caller's. Behind a public proxy of the operator's own the tail is still
/// that proxy's address, which its realip setting turns into the visitor. The
/// operator's statement is theirs to have made true -- a tunnel with no public
/// port, a secret header the CDN adds and the proxy requires -- and with it
/// untrue the caller writes its own address and the lockout means nothing.
///
/// Both addresses are canonicalized: the default dual-stack `[::]` listener
/// reports IPv4 peers, 127.0.0.1 included, as `::ffff:a.b.c.d`, which no IPv6
/// range below recognizes as local.
pub fn client_ip(app: &crate::App, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if app.db.get("origin_cdn_only").as_deref() == Some("on") {
        let visitor = written(headers, "cf-connecting-ip").next();
        if let Some(ip) = visitor.or_else(|| written(headers, "x-forwarded-for").last()) {
            return ip;
        }
    }
    let peer = peer.to_canonical();
    if !behind_local_proxy(peer) {
        return peer;
    }
    // The last line: a proxy that adds a line of its own, HAProxy's
    // `option forwardfor` for one, leaves the caller's lines ahead of it.
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map_or(peer, |ip| ip.to_canonical())
}

/// The public addresses written in a header, in order, however many lines and
/// commas it spans. Private and unparseable entries are passed over.
fn written<'a>(headers: &'a HeaderMap, name: &str) -> impl Iterator<Item = IpAddr> + 'a {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| v.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .filter(|ip| crate::agent_ws::public(*ip))
}

/// Where a node's connection came from: its exit on the panel, and the address
/// its country falls back to. Called only once the node's token has checked out.
///
/// What a proxy in front of the hub says, believed: `CF-Connecting-IP` if there
/// is one, else the first public address in `X-Forwarded-For`, which is where a
/// CDN puts the address it received the connection from. Behind a CDN,
/// `client, edge` is thus the client with nothing configured, where
/// [`client_ip`] sees the edge.
///
/// That would be no way to read a throttle's key, which anyone can write to
/// lock others out or to slip past a lockout. Here a forged value costs the
/// forger only a wrong address beside their own node: a token holder reports
/// any public address of its own in the hello already, and the country lookup
/// follows what was believed, as it did for `CF-Connecting-IP`.
pub fn node_ip(app: &crate::App, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    let written_by_proxy = written(headers, "cf-connecting-ip").next();
    written_by_proxy
        .or_else(|| written(headers, "x-forwarded-for").next())
        .unwrap_or_else(|| client_ip(app, headers, peer))
}

/// Loopback or a private network, where a reverse proxy resides.
fn behind_local_proxy(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        // Unique-local (fc00::/7) and link-local (fe80::/10); the stable
        // standard library provides no predicate for either.
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            v6.is_loopback() || head & 0xfe00 == 0xfc00 || head & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_round_trips_fails_closed_and_never_repeats_a_salt() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("Correct horse battery staple", &hash));
        assert!(!verify_password("", &hash));
        // A corrupt or empty stored hash must fail closed.
        assert!(!verify_password("anything", "not-a-hash"));
        assert!(!verify_password("anything", ""));
        // The salt is per hash, so cracking one row does not reveal every other
        // row sharing that password.
        assert_ne!(hash_password("same").unwrap(), hash_password("same").unwrap());
    }

    /// One address through the full lockout lifecycle: attempts up to the limit
    /// are allowed, the next locks the address out, the window expires on its
    /// own, and a success clears it early. The window is shortened so expiry is
    /// reachable within the test.
    #[test]
    fn a_lockout_lands_expires_on_its_own_and_clears_on_success() {
        let window = Duration::from_millis(60);
        let t = Throttle { window, ..Default::default() };
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        let stale: IpAddr = "203.0.113.9".parse().unwrap();
        let held = || t.seen.lock().unwrap().len();

        t.record_failure(stale);
        for _ in 0..MAX_ATTEMPTS {
            assert!(!t.locked(ip), "attempts up to the limit are still allowed");
            t.record_failure(ip);
        }
        assert!(t.locked(ip), "the attempt past the limit is shut out");
        assert!(!t.locked(other), "the lockout must not spread to other addresses");

        // A lockout is a delay rather than a ban: the address is readmitted
        // automatically.
        std::thread::sleep(window * 2);
        assert!(!t.locked(ip), "an expired lockout must lift on its own");

        // `stale` is never queried, so only the sweep on entry can remove it.
        // Without it the map grows by one entry per address presented, for the
        // life of the process.
        assert_eq!(held(), 1, "the expired lockout is gone, stale is still held");
        t.record_failure(other);
        assert_eq!(held(), 1, "the stale address is swept, not carried");

        // A correct password clears the count, so two typos do not make the next
        // mistake a lockout.
        t.clear(other);
        assert_eq!(held(), 0);
    }

    /// A challenge that is gone -- used up, expired, or cleared by a sign-in that
    /// succeeded -- must not be recreated by a failure that was already in
    /// flight. Recreating it would hand the cookie a fresh five attempts and
    /// another 300 seconds, and a challenge that already signed someone in would
    /// be able to sign them in again.
    #[test]
    fn a_spent_challenge_is_not_revived_by_a_late_failure() {
        let c = Challenges::default();
        let now = Utc::now().timestamp();
        c.issue("used-up".into(), now + CHALLENGE_SECS);
        for _ in 0..MAX_CODE_ATTEMPTS {
            c.record_failure("used-up", now);
        }
        assert_eq!(c.attempts_left("used-up", now), None, "five attempts spend it");
        assert_eq!(c.record_failure("used-up", now), MAX_CODE_ATTEMPTS);
        assert_eq!(c.attempts_left("used-up", now), None, "and a late failure does not bring it back");

        c.issue("signed-in".into(), now + CHALLENGE_SECS);
        c.clear("signed-in");
        c.record_failure("signed-in", now);
        assert_eq!(c.attempts_left("signed-in", now), None, "nor does one that already signed someone in");

        // One never issued at all is not invented by a failure either.
        assert_eq!(c.record_failure("never", now), MAX_CODE_ATTEMPTS);
        assert_eq!(c.attempts_left("never", now), None);
    }

    /// The claims are read-modify-write over a shared row, so two sign-ins that
    /// arrive together must not both win: the same code twice would be two
    /// sessions, and two different recovery codes would each write back a list
    /// still holding the other's -- reviving a code that was spent.
    #[test]
    fn a_one_time_code_is_claimed_once_however_many_callers_arrive_together() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let app = Arc::new(crate::App::for_test(crate::db::Db::open(":memory:").unwrap()));
        let secret = totp::new_secret();
        app.db.set("totp_secret", &secret).unwrap();
        app.db.set("totp_enabled", "on").unwrap();
        let codes = totp::new_recovery_codes();
        let digests: Vec<String> = codes.iter().map(|c| totp::recovery_digest(c)).collect();
        app.db.set("totp_recovery", &serde_json::to_string(&digests).unwrap()).unwrap();

        let live = totp::code(&secret, Utc::now().timestamp() as u64 + totp::STEP).unwrap();
        let wins = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    if claim_code(&app, &live) {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 1, "one code, one sign-in");

        // Two different recovery codes at once: both are spent, and neither
        // write puts the other's code back.
        let wins = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for code in [&codes[0], &codes[1], &codes[0], &codes[1]] {
                scope.spawn(|| {
                    if claim_recovery_code(&app, code) {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 2, "each code is good once");
        assert_eq!(recovery_left(&app), codes.len() - 2);
    }

    /// The gate must refuse rather than queue: a queue admits the same flood,
    /// and each attempt that lands costs 19 MiB which remains in a thread's
    /// arena for the life of the process.
    #[test]
    fn the_password_gate_refuses_a_flood_rather_than_queueing_it() {
        // No other test may be inside a password check while this one measures
        // the gate.
        let _alone = PASSWORD_TESTS.blocking_lock();
        let held: Vec<_> =
            (0..PASSWORD_CHECKS).map(|_| PASSWORD_GATE.try_acquire().expect("up to the limit")).collect();
        assert!(PASSWORD_GATE.try_acquire().is_err(), "the attempt past the limit must be refused");
        drop(held);
        assert!(PASSWORD_GATE.try_acquire().is_ok(), "permits come back when the checks finish");
    }

    /// Both ends of the same redirect: every form GitHub can send must parse,
    /// or it never reaches the handler and can be neither logged nor explained,
    /// and the reason sent back must survive its query string.
    #[test]
    fn every_callback_shape_parses_and_a_failure_reason_survives_the_round_trip() {
        let parse = |q: &str| serde_urlencoded::from_str::<Callback>(q);

        let ok = parse("code=abc&state=xyz").expect("the happy path");
        assert_eq!(ok.code.as_deref(), Some("abc"));
        assert_eq!(ok.state.as_deref(), Some("xyz"));

        // GitHub reports a refusal with no code.
        let denied = parse("error=access_denied&error_description=the+user+said+no&state=xyz")
            .expect("a refusal must parse, not 400");
        assert_eq!(denied.error.as_deref(), Some("access_denied"));
        assert_eq!(denied.error_description.as_deref(), Some("the user said no"));
        assert!(denied.code.is_none());

        // Truncated or empty callbacks must still reach the handler.
        assert!(parse("state=xyz").is_ok());
        assert!(parse("").is_ok());

        // Anything that would escape the query string must be encoded, or the
        // reason arrives truncated at the first stray separator.
        assert_eq!(urlencode("a&b=c#d"), "a%26b%3Dc%23d");
        assert_eq!(urlencode("用户"), "%E7%94%A8%E6%88%B7");
        let reason = "no allowed GitHub users configured (a&b=c)";
        let back = parse(&format!("error={}", urlencode(reason))).expect("a reason must parse");
        assert_eq!(back.error.as_deref(), Some(reason), "the whole reason comes back");
    }

    /// A session cookie's round trip: the flags it is issued with, sharing a
    /// response with a second cookie, and being extracted from the single header
    /// the browser returns them in.
    #[test]
    fn a_session_cookie_goes_out_locked_down_alongside_others_and_parses_back() {
        let session = set_cookie(COOKIE, "abc123", 3_600, true);
        assert!(session.contains("HttpOnly") && session.contains("SameSite=Lax"));
        assert!(session.contains("Secure"));
        assert!(!set_cookie(COOKIE, "abc123", 3_600, false).contains("Secure"));

        // axum applies an array of header tuples with insert(), keeping only the
        // last Set-Cookie; this helper appends instead.
        let response = with_cookies(StatusCode::OK, [session, set_cookie(STATE_COOKIE, "s", 0, true)]);
        let set: Vec<_> = response.headers().get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(set.len(), 2, "both cookies must reach the browser");
        // Empty entries are skipped rather than emitting a blank header.
        let response = with_cookies(StatusCode::OK, ["a=1".to_owned(), String::new()]);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).iter().count(), 1);

        // And back: the browser returns them all in a single header.
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "other=1; monitor_session=abc123; x=2".parse().unwrap());
        assert_eq!(cookie_value(&h, COOKIE).as_deref(), Some("abc123"));
        assert_eq!(cookie_value(&h, "missing"), None);
        assert_eq!(cookie_value(&HeaderMap::new(), COOKIE), None);
    }

    #[test]
    fn forwarded_header_is_trusted_only_behind_a_local_proxy() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let xff = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", v.parse().unwrap());
            h
        };

        // Nothing arrived with the request: the proxy appended the single
        // address it observed, which is the entire header.
        assert_eq!(client_ip(&app, &xff("198.51.100.9"), ip("127.0.0.1")).to_string(), "198.51.100.9");

        // The caller supplied a header of its own. Both documented proxies
        // append, so the fabricated value sits at the head and the proxy's
        // observation at the tail; reading the head would let a caller choose its
        // own throttle bucket each request, or claim the operator's address.
        let forged = xff("10.0.0.2, 198.51.100.9");
        for peer in ["127.0.0.1", "10.0.0.1", "::1", "fd00::1"] {
            assert_eq!(client_ip(&app, &forged, ip(peer)).to_string(), "198.51.100.9", "{peer}");
        }

        // A dual-stack `[::]` listener reports an IPv4 proxy as `::ffff:a.b.c.d`,
        // which is the same local peer.
        assert_eq!(client_ip(&app, &forged, ip("::ffff:172.18.0.4")).to_string(), "198.51.100.9");
        assert_eq!(client_ip(&app, &HeaderMap::new(), ip("::ffff:203.0.113.5")), ip("203.0.113.5"));

        // A proxy that adds a line of its own puts it after the caller's.
        let mut lines = HeaderMap::new();
        lines.append("x-forwarded-for", "10.0.0.2".parse().unwrap());
        lines.append("x-forwarded-for", "198.51.100.9".parse().unwrap());
        assert_eq!(client_ip(&app, &lines, ip("127.0.0.1")).to_string(), "198.51.100.9");

        // Directly from the internet the entire header is caller-supplied, and
        // honouring any part of it bypasses the lockout.
        assert_eq!(client_ip(&app, &forged, ip("203.0.113.5")), ip("203.0.113.5"));
        assert_eq!(client_ip(&app, &forged, ip("2001:db8::5")), ip("2001:db8::5"));
        // No header at all: the peer address is used.
        assert_eq!(client_ip(&app, &HeaderMap::new(), ip("10.0.0.1")), ip("10.0.0.1"));

        // Cloudflare in front of the local proxy: the tail is its edge. The
        // throttle stays on it, as anyone on Cloudflare's network can write
        // CF-Connecting-IP; a node's address follows the header.
        let mut edge = xff("10.0.0.2, 203.0.113.7, 162.158.88.126");
        edge.insert("cf-connecting-ip", "::ffff:203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&app, &edge, ip("127.0.0.1")), ip("162.158.88.126"));
        assert_eq!(node_ip(&app, &edge, ip("127.0.0.1")), ip("203.0.113.7"));
        // Without the header a node's address is the first public one in the
        // list, private hops ahead of it passed over.
        assert_eq!(node_ip(&app, &forged, ip("127.0.0.1")), ip("198.51.100.9"));
        // And with no proxy to speak of, there is nothing else to go by.
        assert_eq!(node_ip(&app, &HeaderMap::new(), ip("203.0.113.5")), ip("203.0.113.5"));
        assert_eq!(node_ip(&app, &xff("10.0.0.2"), ip("203.0.113.5")), ip("203.0.113.5"));
    }

    /// Behind a CDN a node's address is the first public one of the list, where
    /// the throttle's key stays the edge. Whatever else is written ahead of it is
    /// the node's to choose.
    #[test]
    fn a_nodes_address_sees_through_a_cdn_edge_and_the_throttle_does_not() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "198.51.100.77, 162.158.88.126".parse().unwrap());
        for peer in ["127.0.0.1", "10.0.0.1", "162.158.88.126"] {
            assert_eq!(node_ip(&app, &h, ip(peer)), ip("198.51.100.77"), "{peer}");
        }
        assert_eq!(client_ip(&app, &h, ip("127.0.0.1")), ip("162.158.88.126"));
        assert_eq!(client_ip(&app, &h, ip("162.158.88.126")), ip("162.158.88.126"));
        // A list with nothing public in it falls back to the throttle's rule.
        let mut junk = HeaderMap::new();
        junk.insert("x-forwarded-for", "nonsense, 10.0.0.9".parse().unwrap());
        assert_eq!(node_ip(&app, &junk, ip("127.0.0.1")), ip("10.0.0.9"));
    }

    /// With the origin declared reachable by a CDN only, the visitor is what the
    /// CDN wrote, and what the caller put ahead of it never chooses the key.
    #[test]
    fn with_the_origin_declared_cdn_only_the_visitor_is_the_address() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let xff = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", v.parse().unwrap());
            h
        };
        // A tunnel, then the local proxy that appended the tunnel's address,
        // behind a caller-written prefix: the CDN's entry is the one to take.
        let tunnel = xff("192.0.2.1, 198.51.100.77, 127.0.0.1");
        // Off, and not set at all, is the strict rule.
        assert_eq!(client_ip(&app, &tunnel, ip("127.0.0.1")), ip("127.0.0.1"));
        app.db.set("origin_cdn_only", "off").unwrap();
        assert_eq!(client_ip(&app, &tunnel, ip("127.0.0.1")), ip("127.0.0.1"));

        app.db.set("origin_cdn_only", "on").unwrap();
        for peer in ["127.0.0.1", "10.0.0.1", "162.158.88.126"] {
            assert_eq!(client_ip(&app, &tunnel, ip(peer)), ip("198.51.100.77"), "{peer}");
        }
        // The tunnel straight into the hub.
        assert_eq!(client_ip(&app, &xff("192.0.2.1, 198.51.100.77"), ip("127.0.0.1")), ip("198.51.100.77"));
        // Cloudflare writes the header itself, whatever the list says.
        let mut cf = xff("192.0.2.1, 198.51.100.77, 162.158.88.126");
        cf.insert("cf-connecting-ip", "198.51.100.88".parse().unwrap());
        assert_eq!(client_ip(&app, &cf, ip("127.0.0.1")), ip("198.51.100.88"));
        // A private value there is not a visitor.
        cf.insert("cf-connecting-ip", "127.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&app, &cf, ip("127.0.0.1")), ip("162.158.88.126"));
        // A CDN edge that is the proxy's peer is the tail, and stays one bucket.
        let edge = xff("192.0.2.1, 198.51.100.77, 162.158.88.126");
        assert_eq!(client_ip(&app, &edge, ip("127.0.0.1")), ip("162.158.88.126"));
        // Nothing written: the peer, as ever.
        assert_eq!(client_ip(&app, &HeaderMap::new(), ip("203.0.113.5")), ip("203.0.113.5"));
        // The cost of saying it falsely.
        assert_eq!(client_ip(&app, &xff("192.0.2.1"), ip("203.0.113.5")), ip("192.0.2.1"));
    }

    #[test]
    fn an_ipv6_visitor_is_one_bucket_per_64() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let throttle = Throttle::default();
        for n in 0..MAX_ATTEMPTS {
            throttle.record_failure(ip(&format!("2001:db8:1:2::{n:x}")));
        }
        assert!(throttle.locked(ip("2001:db8:1:2:ffff::1")));
        assert!(!throttle.locked(ip("2001:db8:1:3::1")));
    }
}
