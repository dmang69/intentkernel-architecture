//! intentd socket client — used by ikrl to fetch config and report events.

use intentkernel_sdk::config::KernelConfig;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub const SOCKET_PATH: &str = "/tmp/intentkernel-intentd.sock";

/// A connected client session to intentd's Unix socket.
pub struct BrokerClient {
    stream: UnixStream,
}

impl BrokerClient {
    /// Try to connect to intentd.  Returns `None` if the socket is not
    /// reachable (intentd not running).
    pub fn new() -> Option<Self> {
        let stream = UnixStream::connect(SOCKET_PATH).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .ok()?;
        Some(Self { stream })
    }

    /// Send a single command and return the response lines until a blank line
    /// or EOF.
    pub fn command(&mut self, cmd: &str) -> Result<Vec<String>, String> {
        let line = format!("{cmd}\n");
        self.stream
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;
        self.stream.flush().map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(self.stream.try_clone().map_err(|e| e.to_string())?);
        let mut lines = Vec::new();
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = buf.trim_end_matches('\n').trim_end_matches('\r');
                    if trimmed.is_empty() {
                        break;
                    }
                    lines.push(trimmed.to_string());
                    // intentd responds with one line per command for most ops.
                    if lines.len() == 1 && !cmd.starts_with("config get") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        Ok(lines)
    }

    /// Fetch the full config from intentd and parse it into a [`KernelConfig`].
    pub fn fetch_config(&mut self) -> Result<KernelConfig, String> {
        let lines = self.command("config get")?;
        let mut cfg = KernelConfig::default();
        for line in lines {
            if let Some((key, val)) = line.split_once('=') {
                let _ = cfg.set_field(key.trim(), val.trim());
            }
        }
        cfg.sanitize();
        Ok(cfg)
    }
}
