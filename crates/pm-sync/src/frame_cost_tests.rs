// SPDX-License-Identifier: AGPL-3.0-only
//! Differential probe, not a Windows latency or product acceptance test.
use super::*;
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

fn key() -> Key {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(pair.public_key().as_ref());
    Key {
        private: ProtectedBytes::new(document.as_ref().to_vec()).unwrap(),
        spki,
    }
}

struct CountedSocket {
    socket: UnixStream,
    writes: usize,
    bytes: usize,
}
impl Read for CountedSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.socket.read(bytes)
    }
}
impl Write for CountedSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.socket.write(bytes)?;
        self.writes += 1;
        self.bytes += written;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

#[test]
fn real_tls_session_frame_write_cost_differential() {
    let client_key = key();
    let server_key = key();
    let server = server_config(
        certified(&server_key).unwrap(),
        vec![client_key.spki.clone()],
    )
    .unwrap();
    let client = client_config(&client_key, &server_key.spki).unwrap();
    let (client_socket, server_socket) = UnixStream::pair().unwrap();
    for socket in [&client_socket, &server_socket] {
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
    }
    let worker = std::thread::spawn(move || {
        let mut tls =
            rustls::StreamOwned::new(ServerConnection::new(server).unwrap(), server_socket);
        // Both modes share one real authenticated connection. The receiver
        // parses the existing frame and checks independent literal bytes.
        for _ in 0..32 {
            assert_eq!(read_frame(&mut tls).unwrap(), b"synthetic-frame-cost");
            assert_eq!(tls.conn.alpn_protocol(), Some(ALPN));
            write_frame(&mut tls, b"synthetic-reply").unwrap();
        }
    });
    let conn = ClientConnection::new(
        Arc::new(client),
        ServerName::try_from("passwordmanager.invalid").unwrap(),
    )
    .unwrap();
    let mut tls = rustls::StreamOwned::new(
        conn,
        CountedSocket {
            socket: client_socket,
            writes: 0,
            bytes: 0,
        },
    );
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).unwrap();
    }
    assert_eq!(tls.conn.alpn_protocol(), Some(ALPN));
    let mut costs = Vec::new();
    for combined in [false, true] {
        tls.sock.writes = 0;
        tls.sock.bytes = 0;
        for _ in 0..16 {
            if combined {
                // Test-only candidate: same application bytes, one TLS write.
                tls.write_all(b"\x00\x00\x00\x14synthetic-frame-cost")
                    .unwrap();
                tls.flush().unwrap();
            } else {
                write_frame(&mut tls, b"synthetic-frame-cost").unwrap();
            }
            assert_eq!(read_frame(&mut tls).unwrap(), b"synthetic-reply");
        }
        costs.push((tls.sock.writes, tls.sock.bytes));
    }
    worker.join().unwrap();
    eprintln!(
        "FRAME_COST requests_per_mode=16 current_writes={} candidate_writes={} current_tls_bytes={} candidate_tls_bytes={}",
        costs[0].0, costs[1].0, costs[0].1, costs[1].1
    );
    assert!(
        costs[0].0 > costs[1].0,
        "split framing should exhibit its extra transport work"
    );
    assert!(
        costs[0].1 > costs[1].1,
        "extra TLS record has measurable ciphertext overhead"
    );
}
