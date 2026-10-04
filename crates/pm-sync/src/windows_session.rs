// SPDX-License-Identifier: AGPL-3.0-only
//! Native Windows lifecycle for the existing sequential TLS/RPK sync session.
use super::*;

pub(super) fn client(a: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<(), ()> {
    let preparing = timing::Span::new("client_prepare");
    let socket = take(a, "--socket")?;
    let key = read_key(&take(a, "--client-key")?)?;
    let server = read_public(&take(a, "--server-pub")?)?;
    if a.next().is_some() {
        return Err(());
    }
    let config = client_config(&key, &server)?;
    drop(preparing);
    let stop = WindowsStopEvent::create().map_err(|_| ())?;
    let result = (|| {
        let opening = timing::Span::new("client_pipe_open");
        let pipe =
            WindowsClientPipe::connect_sync(socket.to_str().ok_or(())?, &stop).map_err(|_| ())?;
        drop(opening);
        let verifying = timing::Span::new("client_pipe_verify");
        pipe.verify().map_err(|_| ())?;
        timing::count("client_pipe_verify_ok", 1);
        drop(verifying);
        let configuring = timing::Span::new("client_tls_config");
        let conn = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("passwordmanager.invalid").map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let mut tls = rustls::StreamOwned::new(conn, pipe);
        drop(configuring);
        run_with_deadline(&stop, || {
            let _handshake = timing::Span::new("tls_handshake");
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock).map_err(|_| ())?;
            }
            if tls.conn.alpn_protocol() != Some(ALPN) {
                return Err(());
            }
            Ok(())
        })?;
        let mut input = std::io::stdin().lock();
        let mut output = std::io::stdout().lock();
        loop {
            let mut length = [0; 4];
            if input.read(&mut length[..1]).map_err(|_| ())? == 0 {
                // Authenticated TLS EOF lets the server distinguish a completed
                // session from a truncated next frame. No application wire change.
                return run_with_deadline(&stop, || {
                    tls.conn.send_close_notify();
                    tls.flush().map_err(|_| ())
                });
            }
            input.read_exact(&mut length[1..]).map_err(|_| ())?;
            let n = u32::from_be_bytes(length) as usize;
            if n > MAX_FRAME {
                return Err(());
            }
            let mut request = vec![0; n];
            input.read_exact(&mut request).map_err(|_| ())?;
            let mut response = None;
            run_with_deadline(&stop, || {
                tls.sock.verify().map_err(|_| ())?;
                timing::count("client_pipe_verify_ok", 1);
                let _exchange = timing::Span::new("tls_exchange");
                let writing = timing::Span::new("tls_request_write");
                write_frame(&mut tls, &request)?;
                drop(writing);
                let _reading = timing::Span::new("tls_response_read");
                response = Some(read_frame(&mut tls)?);
                Ok(())
            })?;
            write_frame(&mut output, &response.ok_or(())?)?;
        }
    })();
    let closed = stop.close().map_err(|_| ());
    timing::count(
        if closed.is_ok() {
            "client_stop_close_ok"
        } else {
            "client_stop_close_failed"
        },
        1,
    );
    result.and(closed)
}

pub(super) fn serve(
    pipe: WindowsServerPipe,
    db: &Path,
    config: Arc<ServerConfig>,
    stop: &WindowsStopEvent,
) -> Result<(), ()> {
    pipe.verify().map_err(|_| ())?;
    let mut tls = rustls::StreamOwned::new(ServerConnection::new(config).map_err(|_| ())?, pipe);
    let opening = timing::Span::new("server_sqlite_open");
    let store = OpaqueSyncStore::create(db).map_err(|_| ())?;
    // Same WAL keeper as Unix; no read transaction, changed PRAGMA or batching.
    let database = rusqlite::Connection::open(db).map_err(|_| ())?;
    database
        .execute_batch("PRAGMA trusted_schema=OFF")
        .map_err(|_| ())?;
    database
        .query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
        .map_err(|_| ())?;
    drop(opening);
    let result = (|| loop {
        let mut ended = false;
        run_with_deadline(stop, || {
            let reading = timing::Span::new("server_request_read");
            let mut length = [0; 4];
            if tls.read(&mut length[..1]).map_err(|_| ())? == 0 {
                ended = true;
                return Ok(());
            }
            tls.read_exact(&mut length[1..]).map_err(|_| ())?;
            let n = u32::from_be_bytes(length) as usize;
            if n > MAX_FRAME {
                return Err(());
            }
            let mut request = vec![0; n];
            tls.read_exact(&mut request).map_err(|_| ())?;
            drop(reading);
            // Verify before dispatch/commit/reply, while this request's peer is
            // connected. A clean EOF after the last reply needs no live peer.
            let verifying = timing::Span::new("server_pipe_verify");
            tls.sock.verify().map_err(|_| ())?;
            drop(verifying);
            let peer = tls
                .conn
                .peer_certificates()
                .and_then(|v| v.first())
                .ok_or(())?
                .as_ref();
            if tls.conn.alpn_protocol() != Some(ALPN) {
                return Err(());
            }
            let dispatching = timing::Span::new("server_dispatch");
            let response = dispatch_response(&store, peer, &request)?;
            drop(dispatching);
            let _writing = timing::Span::new("server_response_write");
            write_frame(&mut tls, response.as_bytes())
        })?;
        if ended {
            return Ok(());
        }
    })();
    timing::windows_stderr_summary();
    let closed = database.close().map_err(|_| ());
    result.and(closed)
}
