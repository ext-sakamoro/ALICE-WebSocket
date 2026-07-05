//! HTTP upgrade handshake (`compute_accept_key` / `Header` / `HandshakeRequest` / `HandshakeResponse`).

use crate::base64::base64_encode;
use crate::errors::WsError;
use crate::sha1::sha1;

use std::fmt::Write as _;

// Handshake
// ---------------------------------------------------------------------------

/// The magic GUID used in WebSocket handshakes (RFC 6455 Section 4.2.2).
pub const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-5AB5DC11E545";

/// Compute the `Sec-WebSocket-Accept` value from a client key.
#[must_use]
pub fn compute_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WEBSOCKET_GUID.len());
    input.push_str(client_key);
    input.push_str(WEBSOCKET_GUID);
    let hash = sha1(input.as_bytes());
    base64_encode(&hash)
}

/// Parsed HTTP header: name and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A client WebSocket handshake request.
#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub path: String,
    pub host: String,
    pub key: String,
    pub version: String,
    pub protocols: Vec<String>,
    pub extensions: Vec<String>,
    pub headers: Vec<Header>,
}

impl HandshakeRequest {
    /// Generate the HTTP request string.
    #[must_use]
    pub fn to_http(&self) -> String {
        let mut s = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: {}\r\n",
            self.path, self.host, self.key, self.version
        );
        if !self.protocols.is_empty() {
            let _ = write!(
                s,
                "Sec-WebSocket-Protocol: {}\r\n",
                self.protocols.join(", ")
            );
        }
        if !self.extensions.is_empty() {
            let _ = write!(
                s,
                "Sec-WebSocket-Extensions: {}\r\n",
                self.extensions.join(", ")
            );
        }
        for h in &self.headers {
            let _ = write!(s, "{}: {}\r\n", h.name, h.value);
        }
        s.push_str("\r\n");
        s
    }

    /// Create a default handshake request for a given host and path.
    #[must_use]
    pub fn new(host: &str, path: &str, key: &str) -> Self {
        Self {
            path: path.to_owned(),
            host: host.to_owned(),
            key: key.to_owned(),
            version: "13".to_owned(),
            protocols: Vec::new(),
            extensions: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Parse from HTTP request bytes.
    ///
    /// # Errors
    ///
    /// Returns `WsError::HandshakeError` if the request is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, WsError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| WsError::HandshakeError("invalid UTF-8".into()))?;

        let mut lines = text.lines();

        let request_line = lines
            .next()
            .ok_or_else(|| WsError::HandshakeError("empty request".into()))?;

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 || parts[0] != "GET" {
            return Err(WsError::HandshakeError("invalid request line".into()));
        }

        let path = parts[1].to_owned();

        let mut host = String::new();
        let mut key = String::new();
        let mut version = String::new();
        let mut protocols = Vec::new();
        let mut extensions = Vec::new();
        let mut headers = Vec::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                let lower = name.to_ascii_lowercase();
                match lower.as_str() {
                    "host" => value.clone_into(&mut host),
                    "sec-websocket-key" => value.clone_into(&mut key),
                    "sec-websocket-version" => value.clone_into(&mut version),
                    "sec-websocket-protocol" => {
                        protocols = value.split(',').map(|s| s.trim().to_owned()).collect();
                    }
                    "sec-websocket-extensions" => {
                        extensions = value.split(',').map(|s| s.trim().to_owned()).collect();
                    }
                    _ => {
                        headers.push(Header {
                            name: name.to_owned(),
                            value: value.to_owned(),
                        });
                    }
                }
            }
        }

        if key.is_empty() {
            return Err(WsError::HandshakeError("missing Sec-WebSocket-Key".into()));
        }

        Ok(Self {
            path,
            host,
            key,
            version,
            protocols,
            extensions,
            headers,
        })
    }
}

/// A server WebSocket handshake response.
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub accept: String,
    pub protocol: Option<String>,
    pub extensions: Vec<String>,
    pub headers: Vec<Header>,
}

impl HandshakeResponse {
    /// Create a response from a client key.
    #[must_use]
    pub fn from_key(key: &str) -> Self {
        Self {
            accept: compute_accept_key(key),
            protocol: None,
            extensions: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Generate the HTTP response string.
    #[must_use]
    pub fn to_http(&self) -> String {
        let mut s = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
            self.accept
        );
        if let Some(ref proto) = self.protocol {
            let _ = write!(s, "Sec-WebSocket-Protocol: {proto}\r\n");
        }
        if !self.extensions.is_empty() {
            let _ = write!(
                s,
                "Sec-WebSocket-Extensions: {}\r\n",
                self.extensions.join(", ")
            );
        }
        for h in &self.headers {
            let _ = write!(s, "{}: {}\r\n", h.name, h.value);
        }
        s.push_str("\r\n");
        s
    }

    /// Parse a server response to validate the handshake.
    ///
    /// # Errors
    ///
    /// Returns `WsError::HandshakeError` on malformed responses.
    pub fn parse(data: &[u8]) -> Result<Self, WsError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| WsError::HandshakeError("invalid UTF-8".into()))?;

        let mut lines = text.lines();

        let status_line = lines
            .next()
            .ok_or_else(|| WsError::HandshakeError("empty response".into()))?;

        if !status_line.contains("101") {
            return Err(WsError::HandshakeError(format!(
                "expected 101, got: {status_line}"
            )));
        }

        let mut accept = String::new();
        let mut protocol = None;
        let mut extensions = Vec::new();
        let mut headers = Vec::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                let lower = name.to_ascii_lowercase();
                match lower.as_str() {
                    "sec-websocket-accept" => value.clone_into(&mut accept),
                    "sec-websocket-protocol" => protocol = Some(value.to_owned()),
                    "sec-websocket-extensions" => {
                        extensions = value.split(',').map(|s| s.trim().to_owned()).collect();
                    }
                    _ => {
                        headers.push(Header {
                            name: name.to_owned(),
                            value: value.to_owned(),
                        });
                    }
                }
            }
        }

        if accept.is_empty() {
            return Err(WsError::HandshakeError(
                "missing Sec-WebSocket-Accept".into(),
            ));
        }

        Ok(Self {
            accept,
            protocol,
            extensions,
            headers,
        })
    }

    /// Validate the accept key against the original client key.
    ///
    /// # Errors
    ///
    /// Returns `WsError::InvalidAccept` if the accept value doesn't match.
    pub fn validate(&self, client_key: &str) -> Result<(), WsError> {
        let expected = compute_accept_key(client_key);
        if self.accept == expected {
            Ok(())
        } else {
            Err(WsError::InvalidAccept)
        }
    }
}
