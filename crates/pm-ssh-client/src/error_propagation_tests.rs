// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::process::Command;
use std::sync::atomic::AtomicU64;

static NEXT: AtomicU64 = AtomicU64::new(0);
const PROFILE: &str = "version=1\nprofile_id=ssh-lab\nintegrations=ssh-server,linux-system-ssh\nmethods=publickey,password\nhost=127.0.0.1\nport=2222\nusername=pmssh\nhost_key_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nconsumer_uid=3\nserver_version=OpenSSH_10.5p1\n";

#[test]
fn protected_memory_failure_keeps_its_category() {
    let mut passed = true;
    for mode in ["frame", "password", "server"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "error_propagation_tests::protected_memory_child",
                "--ignored",
                "--nocapture",
            ])
            .env("PMW3C_MEMORY_MODE", mode)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stdout.contains("PMW3C_SSH_MEMORY_CONTROL_READY"));
        assert!(stdout.contains("PMW3C_SSH_MEMORY_OBSERVED"));
        if mode == "server" {
            assert!(stderr.contains(
                "category=RESOURCE_UNAVAILABLE cause=protected-memory source=ResourceUnavailable"
            ));
            assert!(!stderr.contains("PMW3C_SYNTHETIC_PASSWORD"));
            assert!(!stderr.contains("PMW3C_SYNTHETIC_PRIVATE_PATH_PAYLOAD"));
        }
        println!("{stdout}{stderr}");
        passed &= output.status.success();
        if !output.status.success() {
            println!("PMW3C_SSH_MEMORY_CHILD_FAILED mode={mode}: {stderr}");
        }
    }
    assert!(passed, "protected memory cause was lost");
}

#[test]
#[ignore = "isolated RLIMIT_MEMLOCK child, invoked by the parent"]
fn protected_memory_child() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        write_frame(&mut writer, b"PMW3C_SYNTHETIC_CONTROL")
            .await
            .unwrap();
        assert_eq!(
            &*read_frame(&mut reader).await.unwrap(),
            b"PMW3C_SYNTHETIC_CONTROL"
        );
        assert_eq!(
            &*copy_password(b"PMW3C_SYNTHETIC_CONTROL").unwrap(),
            b"PMW3C_SYNTHETIC_CONTROL"
        );
        println!("PMW3C_SSH_MEMORY_CONTROL_READY");
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: the test-only child owns this resource limit; no parent is changed.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
            0
        );
        let mode = std::env::var("PMW3C_MEMORY_MODE").unwrap();
        let result = if mode == "frame" {
            // No payload: allocation must fail before attempting its read.
            writer.write_u32(1).await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), read_frame(&mut reader))
                .await
                .unwrap()
        } else if mode == "password" {
            copy_password(b"PMW3C_SYNTHETIC_PASSWORD")
        } else {
            let sockets = Sockets::new();
            // SAFETY: geteuid has no preconditions.
            let uid = unsafe { libc::geteuid() };
            let profile = Arc::new(
                Profile::parse(
                    PROFILE
                        .replace("consumer_uid=3", &format!("consumer_uid={uid}"))
                        .as_bytes(),
                )
                .unwrap(),
            );
            let provider = sockets.0.join("provider.sock");
            let server_provider = provider.clone();
            let consumer = sockets.0.join("consumer.sock");
            let server =
                tokio::spawn(async move { serve(profile, &server_provider, uid, &consumer).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                while !provider.exists() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let mut stream = UnixStream::connect(&provider).await.unwrap();
            stream.write_u32(1).await.unwrap();
            let length = tokio::time::timeout(Duration::from_secs(1), stream.read_u32())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(length, 5);
            let mut response = [0; 5];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [3, 0, 0, 0, 0]);
            assert!(!server.is_finished());
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
            drop(stream);
            drop(sockets);
            println!("PMW3C_SSH_MEMORY_OBSERVED mode=server wire=INDETERMINATE server-live=1");
            return;
        };
        let Err(error) = result else {
            panic!("unlocked owner accepted")
        };
        println!("PMW3C_SSH_MEMORY_OBSERVED mode={mode} category={error}");
        assert_eq!(error.to_string(), "RESOURCE_UNAVAILABLE");
    });
}

struct Sockets(std::path::PathBuf);
impl Sockets {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pmw3c-ssh-errors-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Sockets {
    fn drop(&mut self) {
        for name in ["provider.sock", "consumer.sock"] {
            fs::remove_file(self.0.join(name)).unwrap();
        }
        fs::remove_dir(&self.0).unwrap();
    }
}

#[tokio::test]
async fn consumer_failures_do_not_disappear_in_the_server_loop() {
    for mode in ["header", "parse", "eof"] {
        let sockets = Sockets::new();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let profile = Arc::new(
            Profile::parse(
                PROFILE
                    .replace("consumer_uid=3", &format!("consumer_uid={uid}"))
                    .as_bytes(),
            )
            .unwrap(),
        );
        let provider = sockets.0.join("provider.sock");
        let consumer = sockets.0.join("consumer.sock");
        let server_consumer = consumer.clone();
        let mut server =
            tokio::spawn(async move { serve(profile, &provider, uid, &server_consumer).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !consumer.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut control = UnixStream::connect(&consumer).await.unwrap();
        let mut request = vec![1];
        put_bytes(&mut request, "A".repeat(43).as_bytes()).unwrap();
        write_frame(&mut control, &request).await.unwrap();
        assert_eq!(&*read_frame(&mut control).await.unwrap(), &[1]);
        drop(control);
        println!("PMW3C_CONSUMER_CONTROL_READY mode={mode}");
        let mut stream = UnixStream::connect(&consumer).await.unwrap();
        match mode {
            "header" => stream
                .write_u32(u32::try_from(MAX_FRAME + 1).unwrap())
                .await
                .unwrap(),
            "parse" => write_frame(&mut stream, &[0]).await.unwrap(),
            "eof" => {
                stream.write_all(&[0, 0]).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            _ => unreachable!(),
        }
        let observed =
            if let Ok(joined) = tokio::time::timeout(Duration::from_secs(1), &mut server).await {
                Some(joined.unwrap())
            } else {
                server.abort();
                assert!(server.await.unwrap_err().is_cancelled());
                None
            };
        drop(stream);
        drop(sockets);
        println!(
            "PMW3C_CONSUMER_OBSERVED mode={mode} returned={}",
            observed.is_some()
        );
        let result = observed.expect("consumer failure was discarded by the live server");
        let error = result.unwrap_err();
        let expected = if mode == "eof" {
            "SSH_UNAVAILABLE"
        } else {
            "PROTOCOL_ERROR"
        };
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn typed_causes_do_not_reach_public_error_messages() {
    use std::error::Error as _;
    let marker = "PMW3C_SYNTHETIC_PRIVATE_PATH_PAYLOAD";
    let io = Error::from(std::io::Error::new(std::io::ErrorKind::BrokenPipe, marker));
    assert_eq!(io.to_string(), "SSH_UNAVAILABLE");
    assert_eq!(format!("{io:?}"), "SSH_UNAVAILABLE");
    let source = io
        .source()
        .unwrap()
        .downcast_ref::<std::io::Error>()
        .unwrap();
    assert_eq!(source.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(source.to_string(), marker);
    let ssh = Error::from(russh::Error::Disconnect);
    assert_eq!(ssh.to_string(), "SSH_UNAVAILABLE");
    assert!(ssh.source().unwrap().is::<russh::Error>());
    let memory = Error::Memory(pm_crypto::CryptoError::ResourceUnavailable);
    assert!(memory.source().unwrap().is::<pm_crypto::CryptoError>());
    assert_eq!(memory.to_string(), "RESOURCE_UNAVAILABLE");
    assert_eq!(format!("{memory:?}"), "RESOURCE_UNAVAILABLE");
    io.log_internal("test-io");
    ssh.log_internal("test-ssh");
    memory.log_internal("test-memory");
}
