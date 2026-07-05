//! WebSocket `Extension` + `ExtensionParam` (permessage-deflate 等の準備).

// Extensions
// ---------------------------------------------------------------------------

/// Parsed WebSocket extension with parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub name: String,
    pub params: Vec<ExtensionParam>,
}

/// A single extension parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionParam {
    pub key: String,
    pub value: Option<String>,
}

impl Extension {
    /// Parse an extension header value (e.g., `"permessage-deflate; client_max_window_bits"`).
    #[must_use]
    pub fn parse_list(header: &str) -> Vec<Self> {
        header
            .split(',')
            .filter_map(|ext_str| {
                let ext_str = ext_str.trim();
                if ext_str.is_empty() {
                    return None;
                }
                let mut parts = ext_str.split(';');
                let name = parts.next()?.trim().to_owned();
                if name.is_empty() {
                    return None;
                }
                let params = parts
                    .map(|p| {
                        let p = p.trim();
                        if let Some((k, v)) = p.split_once('=') {
                            ExtensionParam {
                                key: k.trim().to_owned(),
                                value: Some(v.trim().trim_matches('"').to_owned()),
                            }
                        } else {
                            ExtensionParam {
                                key: p.to_owned(),
                                value: None,
                            }
                        }
                    })
                    .collect();
                Some(Self { name, params })
            })
            .collect()
    }

    /// Serialize to header value format.
    #[must_use]
    pub fn to_header_value(extensions: &[Self]) -> String {
        extensions
            .iter()
            .map(|ext| {
                let mut s = ext.name.clone();
                for p in &ext.params {
                    s.push_str("; ");
                    s.push_str(&p.key);
                    if let Some(ref v) = p.value {
                        s.push('=');
                        s.push_str(v);
                    }
                }
                s
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}
