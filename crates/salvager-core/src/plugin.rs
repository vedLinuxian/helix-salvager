//! Plugin system for user-defined file signatures.
//!
//! Allows users to define custom magic byte patterns for file types not
//! built into the engine. Plugins can be loaded from JSON/TOML config files
//! or added programmatically at runtime.
//!
//! ## Config format (JSON)
//!
//! ```json
//! {
//!   "signatures": [
//!     {
//!       "name": "AutoCAD DWG",
//!       "extension": "dwg",
//!       "magic": "41433130",
//!       "offset": 0,
//!       "max_size": 52428800,
//!       "end_marker": null
//!     }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single user-defined file signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSignature {
    /// Human-readable name (e.g., "AutoCAD DWG").
    pub name: String,
    /// File extension without dot (e.g., "dwg").
    pub extension: String,
    /// Magic bytes as hex string (e.g., "89504E47" for PNG).
    pub magic: String,
    /// Byte offset where the magic appears (usually 0).
    #[serde(default)]
    pub offset: usize,
    /// Optional maximum expected file size in bytes. Used to limit
    /// carving range. Default: 50 MB.
    #[serde(default = "default_max_size")]
    pub max_size: usize,
    /// Optional hex-encoded end marker to refine file boundaries.
    #[serde(default)]
    pub end_marker: Option<String>,
    /// Optional MIME type for the file.
    #[serde(default)]
    pub mime_type: Option<String>,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

fn default_max_size() -> usize {
    50 * 1024 * 1024 // 50 MB
}

/// A plugin configuration containing multiple custom signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// List of custom signatures.
    pub signatures: Vec<CustomSignature>,
    /// Optional plugin metadata.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

/// Registry of custom signatures loaded from plugins.
#[derive(Debug, Default, Clone)]
pub struct PluginRegistry {
    signatures: Vec<CustomSignature>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self { signatures: Vec::new() }
    }

    /// Load signatures from a JSON file.
    pub fn load_json<P: AsRef<Path>>(path: P) -> Result<Self, PluginError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| PluginError::Io(e.to_string()))?;
        let config: PluginConfig = serde_json::from_str(&content)
            .map_err(|e| PluginError::Parse(e.to_string()))?;

        let mut registry = Self::new();
        for sig in config.signatures {
            registry.add_signature(sig)?;
        }
        Ok(registry)
    }

    /// Load signatures from a JSON string.
    pub fn load_json_str(json: &str) -> Result<Self, PluginError> {
        let config: PluginConfig = serde_json::from_str(json)
            .map_err(|e| PluginError::Parse(e.to_string()))?;

        let mut registry = Self::new();
        for sig in config.signatures {
            registry.add_signature(sig)?;
        }
        Ok(registry)
    }

    /// Add a single custom signature, validating it first.
    pub fn add_signature(&mut self, sig: CustomSignature) -> Result<(), PluginError> {
        // Validate hex magic
        let magic_bytes = decode_hex(&sig.magic)
            .map_err(|_| PluginError::InvalidMagic(sig.magic.clone()))?;

        if magic_bytes.is_empty() {
            return Err(PluginError::InvalidMagic("empty magic bytes".into()));
        }
        if magic_bytes.len() > 32 {
            return Err(PluginError::InvalidMagic("magic too long (max 32 bytes)".into()));
        }
        if sig.extension.is_empty() || sig.extension.len() > 10 {
            return Err(PluginError::InvalidExtension(sig.extension.clone()));
        }
        if sig.name.is_empty() {
            return Err(PluginError::InvalidName);
        }

        // Validate end marker if present
        if let Some(ref marker) = sig.end_marker {
            decode_hex(marker)
                .map_err(|_| PluginError::InvalidMagic(format!("bad end_marker: {}", marker)))?;
        }

        self.signatures.push(sig);
        Ok(())
    }

    /// Get all registered custom signatures.
    pub fn signatures(&self) -> &[CustomSignature] {
        &self.signatures
    }

    /// Get the decoded magic bytes for a signature.
    pub fn magic_bytes(sig: &CustomSignature) -> Vec<u8> {
        decode_hex(&sig.magic).unwrap_or_default()
    }

    /// Get the decoded end marker bytes for a signature.
    pub fn end_marker_bytes(sig: &CustomSignature) -> Option<Vec<u8>> {
        sig.end_marker.as_ref().and_then(|m| decode_hex(m).ok())
    }

    /// Total number of registered custom signatures.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Merge another registry into this one.
    pub fn merge(&mut self, other: PluginRegistry) {
        self.signatures.extend(other.signatures);
    }

    /// Create a template plugin config with example signatures.
    pub fn template_config() -> PluginConfig {
        PluginConfig {
            name: Some("My Custom Signatures".into()),
            version: Some("1.0.0".into()),
            author: Some("Your Name".into()),
            signatures: vec![
                CustomSignature {
                    name: "AutoCAD DWG".into(),
                    extension: "dwg".into(),
                    magic: "41433130".into(), // AC10
                    offset: 0,
                    max_size: 50 * 1024 * 1024,
                    end_marker: None,
                    mime_type: Some("application/acad".into()),
                    description: Some("AutoCAD drawing file".into()),
                },
                CustomSignature {
                    name: "Blender File".into(),
                    extension: "blend".into(),
                    magic: "424C454E444552".into(), // BLENDER
                    offset: 0,
                    max_size: 100 * 1024 * 1024,
                    end_marker: Some("454E4442".into()), // ENDB
                    mime_type: None,
                    description: Some("Blender 3D project file".into()),
                },
            ],
        }
    }
}

/// Errors from plugin operations.
#[derive(Debug, Clone)]
pub enum PluginError {
    Io(String),
    Parse(String),
    InvalidMagic(String),
    InvalidExtension(String),
    InvalidName,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Parse(e) => write!(f, "Parse error: {}", e),
            Self::InvalidMagic(m) => write!(f, "Invalid magic hex: {}", m),
            Self::InvalidExtension(e) => write!(f, "Invalid extension: {}", e),
            Self::InvalidName => write!(f, "Signature name cannot be empty"),
        }
    }
}

impl std::error::Error for PluginError {}

/// Decode a hex string into bytes.
#[allow(clippy::result_unit_err)]
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, ()> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ())?;
        bytes.push(byte);
    }
    Ok(bytes)
}

// ══════════════════════════════════════════════════════════════
//  TESTS
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("89504E47").unwrap(), vec![0x89, 0x50, 0x4E, 0x47]);
        assert_eq!(decode_hex("FF").unwrap(), vec![0xFF]);
        assert!(decode_hex("GG").is_err());
        assert!(decode_hex("F").is_err()); // odd length
    }

    #[test]
    fn test_add_valid_signature() {
        let mut registry = PluginRegistry::new();
        let sig = CustomSignature {
            name: "Test Format".into(),
            extension: "tst".into(),
            magic: "DEADBEEF".into(),
            offset: 0,
            max_size: 1024,
            end_marker: None,
            mime_type: None,
            description: None,
        };
        assert!(registry.add_signature(sig).is_ok());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_reject_empty_magic() {
        let mut registry = PluginRegistry::new();
        let sig = CustomSignature {
            name: "Bad".into(),
            extension: "bad".into(),
            magic: "".into(),
            offset: 0,
            max_size: 1024,
            end_marker: None,
            mime_type: None,
            description: None,
        };
        assert!(registry.add_signature(sig).is_err());
    }

    #[test]
    fn test_reject_invalid_hex() {
        let mut registry = PluginRegistry::new();
        let sig = CustomSignature {
            name: "Bad".into(),
            extension: "bad".into(),
            magic: "ZZZZ".into(),
            offset: 0,
            max_size: 1024,
            end_marker: None,
            mime_type: None,
            description: None,
        };
        assert!(registry.add_signature(sig).is_err());
    }

    #[test]
    fn test_load_json_str() {
        let json = r#"{
            "signatures": [
                {
                    "name": "AutoCAD DWG",
                    "extension": "dwg",
                    "magic": "41433130"
                }
            ]
        }"#;
        let registry = PluginRegistry::load_json_str(json).unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.signatures()[0].name, "AutoCAD DWG");
    }

    #[test]
    fn test_template_config_serializes() {
        let config = PluginRegistry::template_config();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("AutoCAD"));
        assert!(json.contains("Blender"));
    }

    #[test]
    fn test_merge_registries() {
        let mut r1 = PluginRegistry::new();
        r1.add_signature(CustomSignature {
            name: "A".into(),
            extension: "a".into(),
            magic: "AA".into(),
            offset: 0,
            max_size: 1024,
            end_marker: None,
            mime_type: None,
            description: None,
        }).unwrap();

        let mut r2 = PluginRegistry::new();
        r2.add_signature(CustomSignature {
            name: "B".into(),
            extension: "b".into(),
            magic: "BB".into(),
            offset: 0,
            max_size: 1024,
            end_marker: None,
            mime_type: None,
            description: None,
        }).unwrap();

        r1.merge(r2);
        assert_eq!(r1.len(), 2);
    }
}
