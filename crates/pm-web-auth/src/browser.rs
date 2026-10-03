// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    os::{
        fd::{FromRawFd, RawFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::plaintext::{self, Error, Json, Value, parse_json};
use aws_lc_rs::{digest, hmac, rand};
use pm_crypto::{ProtectedBytes, ProtectedText};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned, version};

use crate::{HttpsUrl, Profile, oidc};

const FLOW_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CDP_MESSAGE: usize = 256 * 1024;

pub(crate) struct Credentials<'a> {
    pub username: &'a str,
    pub password: pm_crypto::ProtectedBytes,
    pub totp: Option<Totp<'a>>,
}

pub(crate) struct Totp<'a> {
    pub secret: pm_crypto::ProtectedBytes,
    pub algorithm: &'a str,
    pub digits: u8,
    pub period: u16,
    pub t0: u64,
}

pub(crate) enum BrowserOutcome {
    Succeeded(ProtectedBytes),
    Waiting,
    Rejected,
    IntegrityFailure,
}

pub(crate) struct PasskeySession {
    browser: Browser,
    session: ProtectedText,
    callback: Option<Callback>,
    state: ProtectedText,
    nonce: ProtectedText,
    verifier: ProtectedText,
}

pub(crate) fn authenticate(
    profile: &Profile,
    credentials: &Credentials<'_>,
) -> Result<BrowserOutcome, Error> {
    if verify_browser(profile).is_err() {
        eprintln!("WEB_AUTH_FAIL stage=browser-artifact");
        return Err(Error::InvalidJson);
    }
    let state = random_token()?;
    let nonce = random_token()?;
    let verifier = random_token()?;
    let challenge =
        plaintext::encode_base64(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref())?;
    let authorize = plaintext::format(format_args!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        profile.value("authorization_endpoint"),
        &*oidc::form_component(profile.value("client_id"))?,
        &*oidc::form_component(profile.value("redirect_uri"))?,
        &*oidc::form_component(profile.value("scopes"))?,
        &*oidc::form_component(&state)?,
        &*oidc::form_component(&nonce)?,
        &*oidc::form_component(&challenge)?,
    ))?;
    let callback = Callback::start(profile, &state).inspect_err(|_| {
        eprintln!("WEB_AUTH_FAIL stage=callback-start");
    })?;
    let mut browser = Browser::launch(profile).inspect_err(|_| {
        eprintln!("WEB_AUTH_FAIL stage=browser-launch");
    })?;
    let result = run_flow(
        profile,
        credentials,
        &authorize,
        &state,
        &nonce,
        &verifier,
        callback,
        &mut browser,
    );
    browser.stop();
    if result.is_err() {
        eprintln!("WEB_AUTH_FAIL stage=flow");
    }
    result
}

/// Starts the fixed Keycloak `WebAuthn` browser flow. The browser remains owned
/// by the trusted adapter while custody pauses the outer attempt for the real
/// human ceremony.
pub(crate) fn authenticate_passkey(
    profile: &Profile,
    username: &str,
    item: [u8; 16],
) -> Result<(BrowserOutcome, Option<PasskeySession>), Error> {
    if !profile.is_passkey() || verify_browser(profile).is_err() {
        return Err(Error::InvalidJson);
    }
    let state = random_token()?;
    let nonce = random_token()?;
    let verifier = random_token()?;
    let challenge =
        plaintext::encode_base64(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref())?;
    let authorize = plaintext::format(format_args!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        profile.value("authorization_endpoint"),
        &*oidc::form_component(profile.value("client_id"))?,
        &*oidc::form_component(profile.value("redirect_uri"))?,
        &*oidc::form_component(profile.value("scopes"))?,
        &*oidc::form_component(&state)?,
        &*oidc::form_component(&nonce)?,
        &*oidc::form_component(&challenge)?,
    ))?;
    let callback = Callback::start(profile, &state)?;
    let mut browser = Browser::launch_passkey(profile, item)?;
    let session = attach(&mut browser, &authorize)?;
    passkey_username(&mut browser, &session, profile, username)?;
    let mut value = PasskeySession {
        browser,
        session,
        callback: Some(callback),
        state,
        nonce,
        verifier,
    };
    match value.poll(profile)? {
        BrowserOutcome::Waiting => Ok((BrowserOutcome::Waiting, Some(value))),
        outcome => Ok((outcome, None)),
    }
}

impl PasskeySession {
    pub(crate) fn poll(&mut self, profile: &Profile) -> Result<BrowserOutcome, Error> {
        let deadline = Instant::now() + Duration::from_millis(500);
        let issuer = profile.url("issuer").map_err(|_| Error::InvalidJson)?;
        let issuer_origin = format!("https://{}:{}", issuer.host(), issuer.port());
        let callback = profile
            .url("redirect_uri")
            .map_err(|_| Error::InvalidJson)?;
        let callback_origin = format!("https://{}:{}", callback.host(), callback.port());
        let script = r"(()=>JSON.stringify({origin:location.origin,top:window.top===window.self,ready:document.readyState,waiting:document.documentElement.dataset.pmPasskeyState||'',error:(document.querySelector('#input-error,#error')?.textContent||'').trim(),webauth:document.querySelector('form#webauth')?.action||''}))()";
        while Instant::now() < deadline {
            let raw = self.browser.evaluate(&self.session, script)?;
            let view = parse_json(raw.as_bytes())?;
            if !bool_field(&view, "top")? {
                return Ok(BrowserOutcome::IntegrityFailure);
            }
            let origin = field(&view, "origin")?;
            if origin == callback_origin {
                let callback = self.callback.take().ok_or(Error::InvalidJson)?;
                let (code, observed_state) = callback.receive()?;
                if observed_state != self.state || code.is_empty() {
                    return Ok(BrowserOutcome::IntegrityFailure);
                }
                let now = i64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| Error::InvalidJson)?
                        .as_secs(),
                )
                .map_err(|_| Error::InvalidJson)?;
                return match oidc::exchange_code(profile, &code, &self.verifier, &self.nonce, now) {
                    Ok(result) => Ok(BrowserOutcome::Succeeded(
                        result.encode().map_err(Error::from)?,
                    )),
                    Err(oidc::OidcError::Network) => Err(Error::Io),
                    Err(oidc::OidcError::ResourceUnavailable) => Err(Error::ResourceUnavailable),
                    Err(_) => Ok(BrowserOutcome::IntegrityFailure),
                };
            }
            if origin != issuer_origin {
                return Ok(BrowserOutcome::IntegrityFailure);
            }
            if !field(&view, "error")?.is_empty() {
                return Ok(BrowserOutcome::Rejected);
            }
            let form = field(&view, "webauth")?;
            if !form.is_empty() {
                validate_form(form, &issuer_origin)?;
            }
            if field(&view, "waiting")? == "waiting" {
                return Ok(BrowserOutcome::Waiting);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Ok(BrowserOutcome::Waiting)
    }
}

fn attach(browser: &mut Browser, authorize: &str) -> Result<ProtectedText, Error> {
    let target = browser.command(
        "Target.createTarget",
        vec![("url", Value::String(authorize))],
        None,
    )?;
    let target = plaintext::text(
        target
            .field("result")
            .and_then(|value| value.field("targetId"))
            .and_then(Json::string)
            .ok_or(Error::InvalidJson)?,
    )?;
    let attached = browser.command(
        "Target.attachToTarget",
        vec![
            ("targetId", Value::String(&target)),
            ("flatten", Value::Bool(true)),
        ],
        None,
    )?;
    let session = plaintext::text(
        attached
            .field("result")
            .and_then(|value| value.field("sessionId"))
            .and_then(Json::string)
            .ok_or(Error::InvalidJson)?,
    )?;
    browser.command("Page.enable", Vec::new(), Some(&session))?;
    browser.command("Runtime.enable", Vec::new(), Some(&session))?;
    browser.command(
        "Browser.setDownloadBehavior",
        vec![("behavior", Value::String("deny"))],
        None,
    )?;
    Ok(session)
}

fn passkey_username(
    browser: &mut Browser,
    session: &str,
    profile: &Profile,
    username: &str,
) -> Result<(), Error> {
    let issuer = profile.url("issuer").map_err(|_| Error::InvalidJson)?;
    let issuer_origin = format!("https://{}:{}", issuer.host(), issuer.port());
    let deadline = Instant::now() + FLOW_TIMEOUT;
    let inspect = r"(()=>JSON.stringify({origin:location.origin,href:location.href,top:window.top===window.self,form:document.querySelector('form#kc-form-login')?.action||'',username:document.querySelector('input#username')?.type||'',password:!!document.querySelector('input#password'),button:!!document.querySelector('input#kc-login,button#kc-login')}))()";
    while Instant::now() < deadline {
        let raw = browser.evaluate(session, inspect)?;
        let view = parse_json(raw.as_bytes())?;
        if field(&view, "origin")? == "null" && field(&view, "href")? == "about:blank" {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }
        if !bool_field(&view, "top")? || field(&view, "origin")? != issuer_origin {
            return Err(Error::InvalidJson);
        }
        if !field(&view, "form")?.is_empty() {
            validate_form(field(&view, "form")?, &issuer_origin)?;
            if field(&view, "username")? != "text"
                || bool_field(&view, "password")?
                || !bool_field(&view, "button")?
            {
                return Err(Error::InvalidJson);
            }
            let username = js_string(username)?;
            let script = plaintext::format(format_args!(
                "(()=>{{const u=document.querySelector('input#username');const f=document.querySelector('form#kc-form-login');if(!u||!f)throw new Error('shape');u.value={};u.dispatchEvent(new Event('input',{{bubbles:true}}));f.requestSubmit(document.querySelector('input#kc-login,button#kc-login'));return 'ok';}})()",
                &*username
            ))?;
            browser.evaluate(session, &script)?;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let click = r"(()=>{const f=document.querySelector('form#webauth');const b=document.querySelector('#authenticateWebAuthnButton');const loaded=performance.getEntriesByType('resource').some(e=>new URL(e.name).pathname.endsWith('/js/webauthnAuthenticate.js'));if(!f||!b||document.readyState!=='complete'||!loaded||globalThis.__PM_PASSKEY_ADAPTER_INSTALLED__!==true)return 'wait';if(window.top!==window.self)throw new Error('frame');b.click();return 'clicked';})()";
    let deadline = Instant::now() + FLOW_TIMEOUT;
    while Instant::now() < deadline {
        let result = browser.evaluate(session, click)?;
        if &*result == "clicked" {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(Error::InvalidJson)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_flow(
    profile: &Profile,
    credentials: &Credentials<'_>,
    authorize: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
    callback: Callback,
    browser: &mut Browser,
) -> Result<BrowserOutcome, Error> {
    let target = browser
        .command(
            "Target.createTarget",
            vec![("url", Value::String(authorize))],
            None,
        )
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=cdp-create-target"))?;
    let target = plaintext::text(
        target
            .field("result")
            .and_then(|value| value.field("targetId"))
            .and_then(Json::string)
            .ok_or_else(|| eprintln!("WEB_AUTH_FAIL stage=cdp-target-id"))?,
    )?;
    let attached = browser
        .command(
            "Target.attachToTarget",
            vec![
                ("targetId", Value::String(&target)),
                ("flatten", Value::Bool(true)),
            ],
            None,
        )
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=cdp-attach"))?;
    let session = plaintext::text(
        attached
            .field("result")
            .and_then(|value| value.field("sessionId"))
            .and_then(Json::string)
            .ok_or_else(|| eprintln!("WEB_AUTH_FAIL stage=cdp-session"))?,
    )?;
    browser
        .command("Page.enable", Vec::new(), Some(&session))
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=cdp-page-enable"))?;
    browser
        .command("Runtime.enable", Vec::new(), Some(&session))
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=cdp-runtime-enable"))?;
    browser
        .command(
            "Browser.setDownloadBehavior",
            vec![("behavior", Value::String("deny"))],
            None,
        )
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=cdp-download-deny"))?;

    let login = wait_for_view(browser, &session, profile, "login")
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=login-preflight"))?;
    if login != "login" {
        return Ok(BrowserOutcome::Waiting);
    }
    let username = js_string(credentials.username)?;
    let password_text =
        std::str::from_utf8(&credentials.password).map_err(|_| Error::InvalidJson)?;
    let password = js_string(password_text)?;
    let script = plaintext::format(format_args!(
        "(()=>{{const u=document.querySelector('input#username');const p=document.querySelector('input#password');const f=document.querySelector('form#kc-form-login');if(!u||!p||!f)throw new Error('shape');u.value={};p.value={};u.dispatchEvent(new Event('input',{{bubbles:true}}));p.dispatchEvent(new Event('input',{{bubbles:true}}));f.requestSubmit(document.querySelector('input#kc-login,button#kc-login'));return 'ok';}})()",
        &*username, &*password
    ))?;
    browser
        .evaluate(&session, &script)
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=login-submit"))?;

    let next = wait_for_view(browser, &session, profile, "otp-or-callback")
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=post-password-view"))?;
    eprintln!("WEB_AUTH_STAGE post-password={next}");
    match next.as_str() {
        "otp" => {
            let totp = credentials.totp.as_ref().ok_or(Error::InvalidJson)?;
            eprintln!(
                "WEB_AUTH_STAGE otp-metadata algorithm={} digits={} period={} t0={} secret-bytes={}",
                totp.algorithm,
                totp.digits,
                totp.period,
                totp.t0,
                totp.secret.len()
            );
            let code = totp_code(totp)?;
            let escaped_code = js_string(&code)?;
            let script = plaintext::format(format_args!(
                "(()=>{{const o=document.querySelector('input#otp');const f=document.querySelector('form#kc-otp-login-form');if(!o||!f)throw new Error('shape');o.value={};o.dispatchEvent(new Event('input',{{bubbles:true}}));f.requestSubmit(document.querySelector('input#kc-login,button#kc-login'));return 'ok';}})()",
                &*escaped_code
            ))?;
            browser
                .evaluate(&session, &script)
                .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=otp-submit"))?;
            drop(escaped_code);
            drop(script);
            drop(code);
            let after_otp = wait_for_view(browser, &session, profile, "callback")
                .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=post-otp-view"))?;
            if after_otp == "rejected" {
                return Ok(BrowserOutcome::Rejected);
            }
            if after_otp != "callback" {
                return Ok(BrowserOutcome::Waiting);
            }
        }
        "callback" => {}
        "rejected" => return Ok(BrowserOutcome::Rejected),
        _ => return Ok(BrowserOutcome::Waiting),
    }
    let (code, observed_state) = callback
        .receive()
        .inspect_err(|_| eprintln!("WEB_AUTH_FAIL stage=callback-receive"))?;
    if &*observed_state != state || code.is_empty() {
        eprintln!("WEB_AUTH_FAIL stage=callback-binding");
        return Ok(BrowserOutcome::IntegrityFailure);
    }
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidJson)?
            .as_secs(),
    )
    .map_err(|_| Error::InvalidJson)?;
    match oidc::exchange_code(profile, &code, verifier, nonce, now) {
        Ok(result) => Ok(BrowserOutcome::Succeeded(
            result.encode().map_err(Error::from)?,
        )),
        Err(oidc::OidcError::ResourceUnavailable) => Err(Error::ResourceUnavailable),
        Err(oidc::OidcError::Network) => {
            eprintln!("WEB_AUTH_FAIL stage=oidc-network");
            Err(Error::InvalidJson)
        }
        Err(error @ (oidc::OidcError::InvalidResponse | oidc::OidcError::InvalidToken)) => {
            eprintln!("WEB_AUTH_FAIL stage=oidc-validation error={error:?}");
            Ok(BrowserOutcome::IntegrityFailure)
        }
    }
}

fn wait_for_view(
    browser: &mut Browser,
    session: &str,
    profile: &Profile,
    phase: &str,
) -> Result<String, Error> {
    let deadline = Instant::now() + FLOW_TIMEOUT;
    let issuer = profile.url("issuer").map_err(|_| Error::InvalidJson)?;
    let issuer_origin = format!("https://{}:{}", issuer.host(), issuer.port());
    let callback = profile
        .url("redirect_uri")
        .map_err(|_| Error::InvalidJson)?;
    let callback_origin = format!("https://{}:{}", callback.host(), callback.port());
    let script = r"(()=>{const login=document.querySelector('form#kc-form-login');const otp=document.querySelector('form#kc-otp-login-form');const otpInput=document.querySelector('input#otp');const user=document.querySelector('input#username');const pass=document.querySelector('input#password');const code=document.querySelector('#input-error,#input-error-otp-code');const challenge=document.querySelector('form#kc-passwd-update-form,form#kc-totp-settings-form,form#kc-register-form,form#kc-update-profile-form');return JSON.stringify({origin:location.origin,href:location.href,top:window.top===window.self,ready:document.readyState,login:!!login,loginAction:login?login.action:'',user:user?user.type:'',pass:pass?pass.type:'',otp:!!otp,otpAction:otp?otp.action:'',otpLength:otpInput?String(otpInput.value.length):'',challenge:challenge?challenge.id:'',rejected:!!code&&code.textContent.trim().length>0});})()";
    while Instant::now() < deadline {
        let raw = browser.evaluate(session, script)?;
        let view = parse_json(raw.as_bytes())?;
        let origin = field(&view, "origin")?;
        let top = bool_field(&view, "top")?;
        let ready = field(&view, "ready")?;
        if !top {
            eprintln!("WEB_AUTH_PREFLIGHT top=false");
            return Err(Error::InvalidJson);
        }
        if origin == callback_origin {
            return Ok("callback".into());
        }
        if origin == "null" && field(&view, "href")? == "about:blank" {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        if origin != issuer_origin {
            eprintln!("WEB_AUTH_PREFLIGHT origin-mismatch=true");
            return Err(Error::InvalidJson);
        }
        if ready == "complete" || ready == "interactive" {
            if bool_field(&view, "rejected")? {
                return Ok("rejected".into());
            }
            if bool_field(&view, "login")? {
                validate_form(field(&view, "loginAction")?, &issuer_origin)?;
                if field(&view, "user")? != "text" || field(&view, "pass")? != "password" {
                    return Err(Error::InvalidJson);
                }
                if phase == "login" {
                    return Ok("login".into());
                }
            }
            if bool_field(&view, "otp")? && phase == "otp-or-callback" {
                validate_form(field(&view, "otpAction")?, &issuer_origin)?;
                return Ok("otp".into());
            }
            if !field(&view, "challenge")?.is_empty() {
                return Ok("challenge".into());
            }
            if phase == "otp-or-callback" {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Ok(raw) = browser.evaluate(session, script)
        && let Ok(view) = parse_json(raw.as_bytes())
    {
        eprintln!(
            "WEB_AUTH_PREFLIGHT timeout phase={phase} otp={} otp-length={} rejected={} challenge={}",
            bool_field(&view, "otp").unwrap_or(false),
            field(&view, "otpLength").unwrap_or("?"),
            bool_field(&view, "rejected").unwrap_or(false),
            !field(&view, "challenge").unwrap_or("").is_empty()
        );
    } else {
        eprintln!("WEB_AUTH_PREFLIGHT timeout phase={phase}");
    }
    Err(Error::InvalidJson)
}

fn validate_form(action: &str, issuer_origin: &str) -> Result<(), Error> {
    let action = HttpsUrl::parse(action).map_err(|_| Error::InvalidJson)?;
    let origin = format!("https://{}:{}", action.host(), action.port());
    if origin != issuer_origin {
        return Err(Error::InvalidJson);
    }
    Ok(())
}

fn field<'a>(json: &'a Json, name: &str) -> Result<&'a str, Error> {
    json.field(name)
        .and_then(Json::string)
        .ok_or(Error::InvalidJson)
}

fn bool_field(json: &Json, name: &str) -> Result<bool, Error> {
    json.field(name)
        .and_then(Json::bool)
        .ok_or(Error::InvalidJson)
}

fn random_token() -> Result<ProtectedText, Error> {
    let mut bytes = ProtectedBytes::zeroed(32).map_err(Error::from)?;
    rand::fill(&mut bytes).map_err(|_| Error::InvalidJson)?;
    plaintext::encode_base64(&bytes)
}

fn totp_code(totp: &Totp<'_>) -> Result<ProtectedText, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidJson)?
        .as_secs();
    generate_totp(
        &totp.secret,
        totp.algorithm,
        totp.digits,
        totp.period,
        totp.t0,
        now,
    )
}

pub(crate) fn generate_totp(
    secret: &[u8],
    algorithm: &str,
    digits: u8,
    period: u16,
    t0: u64,
    now: u64,
) -> Result<ProtectedText, Error> {
    let counter = now.checked_sub(t0).ok_or(Error::InvalidJson)? / u64::from(period);
    let algorithm = match algorithm {
        "SHA1" => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "SHA256" => hmac::HMAC_SHA256,
        "SHA512" => hmac::HMAC_SHA512,
        _ => return Err(Error::InvalidJson),
    };
    let key = hmac::Key::new(algorithm, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = usize::from(bytes.last().ok_or(Error::InvalidJson)? & 0x0f);
    let value = u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::InvalidJson)?
            .try_into()
            .map_err(|_| Error::InvalidJson)?,
    ) & 0x7fff_ffff;
    let modulus = 10_u32
        .checked_pow(u32::from(digits))
        .ok_or(Error::InvalidJson)?;
    plaintext::format(format_args!(
        "{:0width$}",
        value % modulus,
        width = usize::from(digits)
    ))
}

fn js_string(value: &str) -> Result<ProtectedText, Error> {
    let bytes = plaintext::encode(|output| plaintext::write_json_string(output, value))?;
    ProtectedText::from_bytes(bytes).map_err(Error::from)
}

fn verify_browser(profile: &Profile) -> Result<(), Error> {
    let path = Path::new(profile.value("browser_path"));
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidJson)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::InvalidJson);
    }
    let bytes = fs::read(path).map_err(|_| Error::InvalidJson)?;
    let actual = digest::digest(&digest::SHA256, &bytes);
    let expected = decode_hex(profile.value("browser_sha256"))?;
    if actual.as_ref() != expected {
        return Err(Error::InvalidJson);
    }
    let version = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("HOME", profile.value("browser_home"))
        .output()
        .map_err(|_| Error::InvalidJson)?;
    let stdout = std::str::from_utf8(&version.stdout).map_err(|_| Error::InvalidJson)?;
    if !version.status.success() || !stdout.contains(profile.value("browser_version")) {
        return Err(Error::InvalidJson);
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<[u8; 32], Error> {
    let mut output = [0_u8; 32];
    if value.len() != 64 {
        return Err(Error::InvalidJson);
    }
    for (index, byte) in output.iter_mut().enumerate() {
        let pair = &value.as_bytes()[index * 2..index * 2 + 2];
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Error::InvalidJson),
    }
}

const EXTENSION_FILES: [&str; 5] = [
    "config.js",
    "content.js",
    "main.js",
    "manifest.json",
    "service.js",
];

fn prepare_extension(profile: &Profile, attempt: &Path, item: [u8; 16]) -> Result<PathBuf, Error> {
    let source = Path::new(profile.value("extension_path"));
    let metadata = fs::symlink_metadata(source).map_err(|_| Error::InvalidJson)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::InvalidJson);
    }
    let mut context = digest::Context::new(&digest::SHA256);
    let mut values = Vec::new();
    for name in EXTENSION_FILES {
        let path = source.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|_| Error::InvalidJson)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o022 != 0 {
            return Err(Error::InvalidJson);
        }
        let bytes = fs::read(path).map_err(|_| Error::InvalidJson)?;
        context.update(name.as_bytes());
        context.update(&[0]);
        context.update(&bytes);
        context.update(&[0]);
        values.push((name, bytes));
    }
    if context.finish().as_ref() != decode_hex(profile.value("extension_sha256"))? {
        return Err(Error::InvalidJson);
    }
    let destination = attempt.join("passkey-extension");
    fs::create_dir(&destination).map_err(|_| Error::InvalidJson)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
        .map_err(|_| Error::InvalidJson)?;
    let issuer = profile.url("issuer").map_err(|_| Error::InvalidJson)?;
    let origin = format!("https://{}:{}", issuer.host(), issuer.port());
    let item = item.iter().fold(String::new(), |mut output, value| {
        write!(output, "{value:02x}").expect("writing to a String cannot fail");
        output
    });
    for (name, mut bytes) in values {
        if name == "config.js" {
            let text = String::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
            bytes = text
                .replace("https://passkey.test:8443", &origin)
                .replace(
                    "rpId: \"passkey.test\"",
                    &format!("rpId: \"{}\"", issuer.host()),
                )
                .replace("itemId: \"\"", &format!("itemId: \"{item}\""))
                .into_bytes();
        } else if name == "manifest.json" {
            let text = String::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
            bytes = text
                .replace("https://passkey.test:8443/*", &format!("{origin}/*"))
                .into_bytes();
        }
        fs::write(destination.join(name), bytes).map_err(|_| Error::InvalidJson)?;
    }
    Ok(destination)
}

struct Browser {
    child: Child,
    input: File,
    output: File,
    next_id: u64,
    profile: PathBuf,
}

impl Browser {
    fn launch(profile: &Profile) -> Result<Self, Error> {
        Self::launch_inner(profile, None)
    }

    fn launch_passkey(profile: &Profile, item: [u8; 16]) -> Result<Self, Error> {
        let mut browser = Self::launch_inner(profile, Some(item))?;
        browser.wait_for_passkey_extension()?;
        Ok(browser)
    }

    fn wait_for_passkey_extension(&mut self) -> Result<(), Error> {
        let deadline = Instant::now() + FLOW_TIMEOUT;
        while Instant::now() < deadline {
            let targets = self.command("Target.getTargets", Vec::new(), None)?;
            let Some(Json::Array(targets)) = targets
                .field("result")
                .and_then(|value| value.field("targetInfos"))
            else {
                return Err(Error::InvalidJson);
            };
            let ready = targets.iter().any(|target| {
                matches!(
                    target.field("type").and_then(Json::string),
                    Some("service_worker" | "background_page")
                ) && target
                    .field("url")
                    .and_then(Json::string)
                    .is_some_and(|url| url.starts_with("chrome-extension://"))
            });
            if ready {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(Error::InvalidJson)
    }

    fn launch_inner(profile: &Profile, item: Option<[u8; 16]>) -> Result<Self, Error> {
        let home = Path::new(profile.value("browser_home"));
        let metadata = fs::symlink_metadata(home).map_err(|_| Error::InvalidJson)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidJson);
        }
        let profile_path = home.join(format!("attempt-{}", &*random_token()?));
        fs::create_dir(&profile_path).map_err(|_| Error::InvalidJson)?;
        fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::InvalidJson)?;
        let (to_child_read, to_child_write) = pipe()?;
        let (from_child_read, from_child_write) = pipe()?;
        let extension = item
            .map(|item| prepare_extension(profile, &profile_path, item))
            .transpose()?;
        let issuer = profile.url("issuer").map_err(|_| Error::InvalidJson)?;
        let callback = profile
            .url("redirect_uri")
            .map_err(|_| Error::InvalidJson)?;
        let resolver = format!(
            "MAP {} 127.0.0.1, MAP {} 127.0.0.1, EXCLUDE localhost",
            issuer.host(),
            callback.host()
        );
        let mut command = Command::new(profile.value("browser_path"));
        command
            .args([
                "--headless=new",
                "--remote-debugging-pipe",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--disable-logging",
                "--disable-breakpad",
                "--disable-crash-reporter",
                "--disable-dev-shm-usage",
            ])
            .arg(format!("--host-resolver-rules={resolver}"));
        if let Some(extension) = &extension {
            command
                .arg(format!(
                    "--disable-extensions-except={}",
                    extension.display()
                ))
                .arg(format!("--load-extension={}", extension.display()));
        } else {
            command.arg("--disable-extensions");
        }
        command
            .arg("about:blank")
            .arg(format!("--user-data-dir={}", profile_path.display()))
            .env_clear()
            .env("HOME", home)
            .env("TMPDIR", home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: only async-signal-safe descriptor operations run after fork.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(to_child_read, 3) < 0 || libc::dup2(from_child_write, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| Error::InvalidJson)?;
        close_fd(to_child_read);
        close_fd(from_child_write);
        // SAFETY: these two descriptors are uniquely transferred to File.
        let input = unsafe { File::from_raw_fd(to_child_write) };
        // SAFETY: these two descriptors are uniquely transferred to File.
        let output = unsafe { File::from_raw_fd(from_child_read) };
        Ok(Self {
            child,
            input,
            output,
            next_id: 1,
            profile: profile_path,
        })
    }

    fn command(
        &mut self,
        method: &str,
        params: Vec<(&str, Value<'_>)>,
        session: Option<&str>,
    ) -> Result<Json, Error> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(Error::InvalidJson)?;
        let id_text = id.to_string();
        let mut fields = vec![
            ("id", Value::Number(&id_text)),
            ("method", Value::String(method)),
            ("params", Value::Object(params)),
        ];
        if let Some(session) = session {
            fields.push(("sessionId", Value::String(session)));
        }
        let request = Value::Object(fields);
        let encoded = request.encode()?;
        self.input
            .write_all(&encoded)
            .and_then(|()| self.input.write_all(&[0]))
            .map_err(|_| Error::InvalidJson)?;
        loop {
            let response = self.read_message()?;
            if response.field("id").and_then(Json::number) == Some(id_text.as_str()) {
                if response.field("error").is_some() {
                    return Err(Error::InvalidJson);
                }
                return Ok(response);
            }
        }
    }

    fn evaluate(&mut self, session: &str, expression: &str) -> Result<ProtectedText, Error> {
        let response = self.command(
            "Runtime.evaluate",
            vec![
                ("expression", Value::String(expression)),
                ("returnByValue", Value::Bool(true)),
                ("awaitPromise", Value::Bool(true)),
            ],
            Some(session),
        )?;
        if response
            .field("result")
            .and_then(|result| result.field("exceptionDetails"))
            .is_some()
        {
            return Err(Error::InvalidJson);
        }
        response
            .field("result")
            .and_then(|result| result.field("result"))
            .and_then(|result| result.field("value"))
            .and_then(Json::string)
            .ok_or(Error::InvalidJson)
            .and_then(plaintext::text)
    }

    fn read_message(&mut self) -> Result<Json, Error> {
        read_cdp_message(&mut self.output)
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.profile);
    }
}

fn read_cdp_message(input: &mut impl Read) -> Result<Json, Error> {
    let bytes = plaintext::read_until(input, MAX_CDP_MESSAGE, &[0])?;
    parse_json(&bytes)
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.stop();
    }
}

fn pipe() -> Result<(RawFd, RawFd), Error> {
    let mut descriptors = [0; 2];
    // SAFETY: valid output array; successful descriptors are owned by caller.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::InvalidJson);
    }
    Ok((descriptors[0], descriptors[1]))
}

fn close_fd(fd: RawFd) {
    // SAFETY: fd is a live pipe end no longer needed by this process.
    unsafe {
        libc::close(fd);
    }
}

struct Callback {
    receiver: mpsc::Receiver<Result<(ProtectedText, ProtectedText), Error>>,
}

impl Callback {
    fn start(profile: &Profile, state: &str) -> Result<Self, Error> {
        let url = profile
            .url("redirect_uri")
            .map_err(|_| Error::InvalidJson)?;
        let cert = fs::read(profile.value("callback_cert")).map_err(|_| Error::InvalidJson)?;
        let mut key_file =
            File::open(profile.value("callback_key")).map_err(|_| Error::InvalidJson)?;
        let key_length =
            usize::try_from(key_file.metadata().map_err(|_| Error::InvalidJson)?.len())
                .map_err(|_| Error::InvalidJson)?;
        let key = plaintext::read_all(&mut key_file, key_length)?;
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13])
            .map_err(|_| Error::InvalidJson)?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            )
            .map_err(|_| Error::InvalidJson)?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, url.port()))
            .map_err(|_| Error::InvalidJson)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::InvalidJson)?;
        let expected_state = plaintext::text(state)?;
        let expected_host = format!("{}:{}", url.host(), url.port());
        let expected_path = url.path().to_owned();
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let deadline = Instant::now() + FLOW_TIMEOUT;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let result = callback_connection(
                            socket,
                            config,
                            &expected_host,
                            &expected_path,
                            &expected_state,
                        );
                        let _ = sender.send(result);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
            let _ = sender.send(Err(Error::InvalidJson));
        });
        Ok(Self { receiver })
    }

    fn receive(self) -> Result<(ProtectedText, ProtectedText), Error> {
        self.receiver
            .recv_timeout(FLOW_TIMEOUT)
            .map_err(|_| Error::InvalidJson)?
    }
}

fn callback_connection(
    socket: std::net::TcpStream,
    config: ServerConfig,
    expected_host: &str,
    expected_path: &str,
    expected_state: &str,
) -> Result<(ProtectedText, ProtectedText), Error> {
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::InvalidJson)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::InvalidJson)?;
    let connection = ServerConnection::new(Arc::new(config)).map_err(|_| Error::InvalidJson)?;
    let mut tls = StreamOwned::new(connection, socket);
    let request = plaintext::read_until(&mut tls, 16 * 1024 - 4, b"\r\n\r\n")?;
    let text = std::str::from_utf8(&request).map_err(|_| Error::InvalidJson)?;
    let (code, state) =
        validate_callback_request(text, expected_host, expected_path, expected_state)?;
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        .and_then(|()| tls.flush())
        .map_err(|_| Error::InvalidJson)?;
    Ok((code, state))
}

fn validate_callback_request(
    text: &str,
    expected_host: &str,
    expected_path: &str,
    expected_state: &str,
) -> Result<(ProtectedText, ProtectedText), Error> {
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or(Error::InvalidJson)?;
    let target = first
        .strip_prefix("GET ")
        .and_then(|value| value.strip_suffix(" HTTP/1.1"))
        .ok_or(Error::InvalidJson)?;
    let host = lines
        .find_map(|line| line.strip_prefix("Host: "))
        .ok_or(Error::InvalidJson)?;
    if host != expected_host {
        return Err(Error::InvalidJson);
    }
    let (path, query) = target.split_once('?').ok_or(Error::InvalidJson)?;
    if path != expected_path {
        return Err(Error::InvalidJson);
    }
    let code = query_value(query, "code")?;
    let state = query_value(query, "state")?;
    if &*state != expected_state {
        return Err(Error::InvalidJson);
    }
    Ok((code, state))
}

fn query_value(query: &str, key: &str) -> Result<ProtectedText, Error> {
    for part in query.split('&') {
        if let Some((name, value)) = part.split_once('=')
            && name == key
        {
            return percent_decode(value);
        }
    }
    Err(Error::InvalidJson)
}
fn percent_decode(value: &str) -> Result<ProtectedText, Error> {
    let decoded = plaintext::encode(|output| {
        let bytes = value.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'%' if index + 2 < bytes.len() => {
                    output.put(&[(nibble(bytes[index + 1])? << 4) | nibble(bytes[index + 2])?])?;
                    index += 3;
                }
                b'+' => {
                    output.put(b" ")?;
                    index += 1;
                }
                byte if byte.is_ascii() && !byte.is_ascii_control() => {
                    output.put(&[byte])?;
                    index += 1;
                }
                _ => return Err(Error::InvalidJson),
            }
        }
        Ok(())
    })?;
    ProtectedText::from_bytes(decoded).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc_6238_sha1_vector() {
        assert!(
            (*super::generate_totp(b"12345678901234567890", "SHA1", 8, 30, 0, 59).unwrap())
                .eq("94287082")
        );
    }

    #[test]
    fn callback_is_bound_to_https_listener_host_path_and_state() {
        let valid = "GET /callback?code=new-code&state=expected HTTP/1.1\r\nHost: callback.test:9443\r\n\r\n";
        let (code, state) =
            super::validate_callback_request(valid, "callback.test:9443", "/callback", "expected")
                .unwrap();
        assert!((*code).eq("new-code") && (*state).eq("expected"));
        for invalid in [
            valid.replace("state=expected", "state=wrong"),
            valid.replace("Host: callback.test", "Host: evil.test"),
            valid.replace("GET /callback?", "GET /other?"),
            valid.replace("code=new-code", "error=denied"),
        ] {
            assert!(
                super::validate_callback_request(
                    &invalid,
                    "callback.test:9443",
                    "/callback",
                    "expected"
                )
                .is_err()
            );
        }
    }
}

#[cfg(test)]
#[path = "browser_memory_tests.rs"]
mod memory_tests;
