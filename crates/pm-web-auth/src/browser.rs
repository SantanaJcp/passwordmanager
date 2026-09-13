// SPDX-License-Identifier: AGPL-3.0-only

use std::{
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

use aws_lc_rs::{digest, hmac, rand};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pm_interface::{Json, encode_json, parse_json};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned, version};
use zeroize::{Zeroize, Zeroizing};

use crate::{HttpsUrl, Profile, oidc};

const FLOW_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CDP_MESSAGE: usize = 256 * 1024;

pub(crate) struct Credentials {
    pub username: String,
    pub password: Zeroizing<Vec<u8>>,
    pub totp: Option<Totp>,
}

pub(crate) struct Totp {
    pub secret: Zeroizing<Vec<u8>>,
    pub algorithm: String,
    pub digits: u8,
    pub period: u16,
    pub t0: u64,
}

pub(crate) enum BrowserOutcome {
    Succeeded(Vec<u8>),
    Waiting,
    Rejected,
    IntegrityFailure,
}

pub(crate) fn authenticate(
    profile: &Profile,
    credentials: &Credentials,
) -> Result<BrowserOutcome, ()> {
    if verify_browser(profile).is_err() {
        eprintln!("WEB_AUTH_FAIL stage=browser-artifact");
        return Err(());
    }
    let state = random_token()?;
    let nonce = random_token()?;
    let verifier = random_token()?;
    let challenge = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
    let authorize = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        profile.value("authorization_endpoint"),
        oidc::form_component(profile.value("client_id")),
        oidc::form_component(profile.value("redirect_uri")),
        oidc::form_component(profile.value("scopes")),
        oidc::form_component(&state),
        oidc::form_component(&nonce),
        oidc::form_component(&challenge),
    );
    let callback = Callback::start(profile, &state).map_err(|()| {
        eprintln!("WEB_AUTH_FAIL stage=callback-start");
    })?;
    let mut browser = Browser::launch(profile).map_err(|()| {
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_flow(
    profile: &Profile,
    credentials: &Credentials,
    authorize: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
    callback: Callback,
    browser: &mut Browser,
) -> Result<BrowserOutcome, ()> {
    let target = browser
        .command(
            "Target.createTarget",
            vec![("url", Json::String(authorize.into()))],
            None,
        )
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=cdp-create-target"))?;
    let target = target
        .field("result")
        .and_then(|value| value.field("targetId"))
        .and_then(Json::string)
        .ok_or_else(|| eprintln!("WEB_AUTH_FAIL stage=cdp-target-id"))?
        .to_owned();
    let attached = browser
        .command(
            "Target.attachToTarget",
            vec![
                ("targetId", Json::String(target)),
                ("flatten", Json::Bool(true)),
            ],
            None,
        )
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=cdp-attach"))?;
    let session = attached
        .field("result")
        .and_then(|value| value.field("sessionId"))
        .and_then(Json::string)
        .ok_or_else(|| eprintln!("WEB_AUTH_FAIL stage=cdp-session"))?
        .to_owned();
    browser
        .command("Page.enable", Vec::new(), Some(&session))
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=cdp-page-enable"))?;
    browser
        .command("Runtime.enable", Vec::new(), Some(&session))
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=cdp-runtime-enable"))?;
    browser
        .command(
            "Browser.setDownloadBehavior",
            vec![("behavior", Json::String("deny".into()))],
            None,
        )
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=cdp-download-deny"))?;

    let login = wait_for_view(browser, &session, profile, "login")
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=login-preflight"))?;
    if login != "login" {
        return Ok(BrowserOutcome::Waiting);
    }
    let username = Zeroizing::new(js_string(&credentials.username));
    let password_text = std::str::from_utf8(&credentials.password).map_err(|_| ())?;
    let password = Zeroizing::new(js_string(password_text));
    let script = Zeroizing::new(format!(
        "(()=>{{const u=document.querySelector('input#username');const p=document.querySelector('input#password');const f=document.querySelector('form#kc-form-login');if(!u||!p||!f)throw new Error('shape');u.value={};p.value={};u.dispatchEvent(new Event('input',{{bubbles:true}}));p.dispatchEvent(new Event('input',{{bubbles:true}}));f.requestSubmit(document.querySelector('input#kc-login,button#kc-login'));return 'ok';}})()",
        username.as_str(),
        password.as_str()
    ));
    browser
        .evaluate(&session, &script)
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=login-submit"))?;

    let next = wait_for_view(browser, &session, profile, "otp-or-callback")
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=post-password-view"))?;
    eprintln!("WEB_AUTH_STAGE post-password={next}");
    match next.as_str() {
        "otp" => {
            let totp = credentials.totp.as_ref().ok_or(())?;
            eprintln!(
                "WEB_AUTH_STAGE otp-metadata algorithm={} digits={} period={} t0={} secret-bytes={}",
                totp.algorithm,
                totp.digits,
                totp.period,
                totp.t0,
                totp.secret.len()
            );
            let mut code = Zeroizing::new(totp_code(totp)?);
            let escaped_code = Zeroizing::new(js_string(&code));
            let script = Zeroizing::new(format!(
                "(()=>{{const o=document.querySelector('input#otp');const f=document.querySelector('form#kc-otp-login-form');if(!o||!f)throw new Error('shape');o.value={};o.dispatchEvent(new Event('input',{{bubbles:true}}));f.requestSubmit(document.querySelector('input#kc-login,button#kc-login'));return 'ok';}})()",
                escaped_code.as_str()
            ));
            browser
                .evaluate(&session, &script)
                .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=otp-submit"))?;
            code.zeroize();
            let after_otp = wait_for_view(browser, &session, profile, "callback")
                .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=post-otp-view"))?;
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
        .map_err(|()| eprintln!("WEB_AUTH_FAIL stage=callback-receive"))?;
    if observed_state != state || code.is_empty() {
        eprintln!("WEB_AUTH_FAIL stage=callback-binding");
        return Ok(BrowserOutcome::IntegrityFailure);
    }
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())?;
    match oidc::exchange_code(profile, &code, verifier, nonce, now) {
        Ok(result) => Ok(BrowserOutcome::Succeeded(result.encode())),
        Err(oidc::OidcError::Network) => {
            eprintln!("WEB_AUTH_FAIL stage=oidc-network");
            Err(())
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
) -> Result<String, ()> {
    let deadline = Instant::now() + FLOW_TIMEOUT;
    let issuer = profile.url("issuer").map_err(|_| ())?;
    let issuer_origin = format!("https://{}:{}", issuer.host(), issuer.port());
    let callback = profile.url("redirect_uri").map_err(|_| ())?;
    let callback_origin = format!("https://{}:{}", callback.host(), callback.port());
    let script = r"(()=>{const login=document.querySelector('form#kc-form-login');const otp=document.querySelector('form#kc-otp-login-form');const otpInput=document.querySelector('input#otp');const user=document.querySelector('input#username');const pass=document.querySelector('input#password');const code=document.querySelector('#input-error,#input-error-otp-code');const challenge=document.querySelector('form#kc-passwd-update-form,form#kc-totp-settings-form,form#kc-register-form,form#kc-update-profile-form');return JSON.stringify({origin:location.origin,href:location.href,top:window.top===window.self,ready:document.readyState,login:!!login,loginAction:login?login.action:'',user:user?user.type:'',pass:pass?pass.type:'',otp:!!otp,otpAction:otp?otp.action:'',otpLength:otpInput?String(otpInput.value.length):'',challenge:challenge?challenge.id:'',rejected:!!code&&code.textContent.trim().length>0});})()";
    while Instant::now() < deadline {
        let raw = browser.evaluate(session, script)?;
        let view = parse_json(raw.as_bytes()).map_err(|_| ())?;
        let origin = field(&view, "origin")?;
        let top = bool_field(&view, "top")?;
        let ready = field(&view, "ready")?;
        if !top {
            eprintln!("WEB_AUTH_PREFLIGHT top=false");
            return Err(());
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
            return Err(());
        }
        if ready == "complete" || ready == "interactive" {
            if bool_field(&view, "rejected")? {
                return Ok("rejected".into());
            }
            if bool_field(&view, "login")? {
                validate_form(field(&view, "loginAction")?, &issuer_origin)?;
                if field(&view, "user")? != "text" || field(&view, "pass")? != "password" {
                    return Err(());
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
    Err(())
}

fn validate_form(action: &str, issuer_origin: &str) -> Result<(), ()> {
    let action = HttpsUrl::parse(action).map_err(|_| ())?;
    let origin = format!("https://{}:{}", action.host(), action.port());
    if origin != issuer_origin {
        return Err(());
    }
    Ok(())
}

fn field<'a>(json: &'a Json, name: &str) -> Result<&'a str, ()> {
    json.field(name).and_then(Json::string).ok_or(())
}

fn bool_field(json: &Json, name: &str) -> Result<bool, ()> {
    json.field(name).and_then(Json::bool).ok_or(())
}

fn random_token() -> Result<String, ()> {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes).map_err(|_| ())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn totp_code(totp: &Totp) -> Result<String, ()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    generate_totp(
        &totp.secret,
        &totp.algorithm,
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
) -> Result<String, ()> {
    let counter = now.checked_sub(t0).ok_or(())? / u64::from(period);
    let algorithm = match algorithm {
        "SHA1" => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "SHA256" => hmac::HMAC_SHA256,
        "SHA512" => hmac::HMAC_SHA512,
        _ => return Err(()),
    };
    let key = hmac::Key::new(algorithm, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = usize::from(bytes.last().ok_or(())? & 0x0f);
    let value = u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    ) & 0x7fff_ffff;
    let modulus = 10_u32.checked_pow(u32::from(digits)).ok_or(())?;
    Ok(format!(
        "{:0width$}",
        value % modulus,
        width = usize::from(digits)
    ))
}

fn js_string(value: &str) -> String {
    String::from_utf8(encode_json(&Json::String(value.to_owned()))).unwrap()
}

fn verify_browser(profile: &Profile) -> Result<(), ()> {
    let path = Path::new(profile.value("browser_path"));
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(());
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    let actual = digest::digest(&digest::SHA256, &bytes);
    let expected = decode_hex(profile.value("browser_sha256"))?;
    if actual.as_ref() != expected {
        return Err(());
    }
    let version = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("HOME", profile.value("browser_home"))
        .output()
        .map_err(|_| ())?;
    let stdout = std::str::from_utf8(&version.stdout).map_err(|_| ())?;
    if !version.status.success() || !stdout.contains(profile.value("browser_version")) {
        return Err(());
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<[u8; 32], ()> {
    let mut output = [0_u8; 32];
    if value.len() != 64 {
        return Err(());
    }
    for (index, byte) in output.iter_mut().enumerate() {
        let pair = &value.as_bytes()[index * 2..index * 2 + 2];
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

struct Browser {
    child: Child,
    input: File,
    output: File,
    next_id: u64,
    profile: PathBuf,
}

impl Browser {
    fn launch(profile: &Profile) -> Result<Self, ()> {
        let home = Path::new(profile.value("browser_home"));
        let metadata = fs::symlink_metadata(home).map_err(|_| ())?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(());
        }
        let profile_path = home.join(format!("attempt-{}", random_token()?));
        fs::create_dir(&profile_path).map_err(|_| ())?;
        fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
        let (to_child_read, to_child_write) = pipe()?;
        let (from_child_read, from_child_write) = pipe()?;
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
                "--disable-extensions",
                "--disable-logging",
                "--disable-breakpad",
                "--disable-crash-reporter",
                "--disable-dev-shm-usage",
                "--host-resolver-rules=MAP auth.test 127.0.0.1, MAP callback.test 127.0.0.1, EXCLUDE localhost",
                "about:blank",
            ])
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
        let child = command.spawn().map_err(|_| ())?;
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
        params: Vec<(&str, Json)>,
        session: Option<&str>,
    ) -> Result<Json, ()> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(())?;
        let mut fields = vec![
            ("id".into(), Json::Number(id.to_string())),
            ("method".into(), Json::String(method.into())),
            (
                "params".into(),
                Json::Object(
                    params
                        .into_iter()
                        .map(|(key, value)| (key.to_owned(), value))
                        .collect(),
                ),
            ),
        ];
        if let Some(session) = session {
            fields.push(("sessionId".into(), Json::String(session.into())));
        }
        let mut request = Json::Object(fields);
        let mut encoded = Zeroizing::new(encode_json(&request));
        encoded.push(0);
        let written = self.input.write_all(&encoded);
        zeroize_json(&mut request);
        written.map_err(|_| ())?;
        loop {
            let response = self.read_message()?;
            if response.field("id").and_then(Json::number) == Some(id.to_string().as_str()) {
                if response.field("error").is_some() {
                    return Err(());
                }
                return Ok(response);
            }
        }
    }

    fn evaluate(&mut self, session: &str, expression: &str) -> Result<String, ()> {
        let response = self.command(
            "Runtime.evaluate",
            vec![
                ("expression", Json::String(expression.into())),
                ("returnByValue", Json::Bool(true)),
                ("awaitPromise", Json::Bool(true)),
            ],
            Some(session),
        )?;
        if response
            .field("result")
            .and_then(|result| result.field("exceptionDetails"))
            .is_some()
        {
            return Err(());
        }
        response
            .field("result")
            .and_then(|result| result.field("result"))
            .and_then(|result| result.field("value"))
            .and_then(Json::string)
            .map(str::to_owned)
            .ok_or(())
    }

    fn read_message(&mut self) -> Result<Json, ()> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            self.output.read_exact(&mut byte).map_err(|_| ())?;
            if byte[0] == 0 {
                break;
            }
            if bytes.len() >= MAX_CDP_MESSAGE {
                return Err(());
            }
            bytes.push(byte[0]);
        }
        parse_json(&bytes).map_err(|_| ())
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.profile);
    }
}

fn zeroize_json(value: &mut Json) {
    match value {
        Json::String(value) | Json::Number(value) => value.zeroize(),
        Json::Array(values) => values.iter_mut().for_each(zeroize_json),
        Json::Object(fields) => fields.iter_mut().for_each(|(key, value)| {
            key.zeroize();
            zeroize_json(value);
        }),
        Json::Null | Json::Bool(_) => {}
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.stop();
    }
}

fn pipe() -> Result<(RawFd, RawFd), ()> {
    let mut descriptors = [0; 2];
    // SAFETY: valid output array; successful descriptors are owned by caller.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(());
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
    receiver: mpsc::Receiver<Result<(String, String), ()>>,
}

impl Callback {
    fn start(profile: &Profile, state: &str) -> Result<Self, ()> {
        let url = profile.url("redirect_uri").map_err(|_| ())?;
        let cert = fs::read(profile.value("callback_cert")).map_err(|_| ())?;
        let key = Zeroizing::new(fs::read(profile.value("callback_key")).map_err(|_| ())?);
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13])
            .map_err(|_| ())?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            )
            .map_err(|_| ())?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, url.port()))
            .map_err(|_| ())?;
        listener.set_nonblocking(true).map_err(|_| ())?;
        let expected_state = state.to_owned();
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
            let _ = sender.send(Err(()));
        });
        Ok(Self { receiver })
    }

    fn receive(self) -> Result<(String, String), ()> {
        self.receiver.recv_timeout(FLOW_TIMEOUT).map_err(|_| ())?
    }
}

fn callback_connection(
    socket: std::net::TcpStream,
    config: ServerConfig,
    expected_host: &str,
    expected_path: &str,
    expected_state: &str,
) -> Result<(String, String), ()> {
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ())?;
    let connection = ServerConnection::new(Arc::new(config)).map_err(|_| ())?;
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while request.len() < 16 * 1024 {
        tls.read_exact(&mut byte).map_err(|_| ())?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&request).map_err(|_| ())?;
    let (code, state) =
        validate_callback_request(text, expected_host, expected_path, expected_state)?;
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        .and_then(|()| tls.flush())
        .map_err(|_| ())?;
    Ok((code, state))
}

fn validate_callback_request(
    text: &str,
    expected_host: &str,
    expected_path: &str,
    expected_state: &str,
) -> Result<(String, String), ()> {
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or(())?;
    let target = first
        .strip_prefix("GET ")
        .and_then(|value| value.strip_suffix(" HTTP/1.1"))
        .ok_or(())?;
    let host = lines
        .find_map(|line| line.strip_prefix("Host: "))
        .ok_or(())?;
    if host != expected_host {
        return Err(());
    }
    let (path, query) = target.split_once('?').ok_or(())?;
    if path != expected_path {
        return Err(());
    }
    let code = query_value(query, "code").ok_or(())?;
    let state = query_value(query, "state").ok_or(())?;
    if state != expected_state {
        return Err(());
    }
    Ok((code, state))
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == key).then(|| percent_decode(value)).flatten()
    })
}

fn percent_decode(value: &str) -> Option<String> {
    let mut output = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                output.push((nibble(bytes[index + 1]).ok()? << 4) | nibble(bytes[index + 2]).ok()?);
                index += 3;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte if byte.is_ascii() && !byte.is_ascii_control() => {
                output.push(byte);
                index += 1;
            }
            _ => return None,
        }
    }
    String::from_utf8(output).ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc_6238_sha1_vector() {
        assert_eq!(
            super::generate_totp(b"12345678901234567890", "SHA1", 8, 30, 0, 59).unwrap(),
            "94287082"
        );
    }

    #[test]
    fn callback_is_bound_to_https_listener_host_path_and_state() {
        let valid = "GET /callback?code=new-code&state=expected HTTP/1.1\r\nHost: callback.test:9443\r\n\r\n";
        assert_eq!(
            super::validate_callback_request(valid, "callback.test:9443", "/callback", "expected"),
            Ok(("new-code".into(), "expected".into()))
        );
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
