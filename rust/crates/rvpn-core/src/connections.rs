//! Read-only connection enrichment from the official service log.

use crate::snapshot::SnapshotState;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ConnectionEntry {
    pub connected: bool,
    pub via: Option<String>,
}

pub fn enrich(state: &mut SnapshotState) {
    let entries = read_latest();
    if entries.is_empty() {
        return;
    }
    for network in &mut state.networks {
        for member in &mut network.members {
            if let Some(entry) = entries.get(&member.node_id) {
                member.connection_ok = Some(entry.connected);
                member.connection_via = entry.via.clone();
            }
        }
    }
}

fn log_directory() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Famatech")
        .join("Radmin VPN")
}

fn read_latest() -> HashMap<u64, ConnectionEntry> {
    let mut files: Vec<_> = match std::fs::read_dir(log_directory()) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_name().to_string_lossy().starts_with("service")
                    && entry.path().extension().is_some_and(|e| e == "log")
            })
            .collect(),
        Err(_) => return HashMap::new(),
    };
    files.sort_by_key(|entry| entry.metadata().and_then(|meta| meta.modified()).ok());
    files.reverse();

    let mut output = HashMap::new();
    for entry in files.into_iter().take(4) {
        let bytes = match std::fs::read(entry.path()) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let text = decode_log(&bytes);
        for line in text.lines().rev() {
            if let Some((id, connection)) = parse_line(line) {
                output.entry(id).or_insert(connection);
            }
        }
    }
    output
}

fn decode_log(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|p| u16::from_be_bytes([p[0], p[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn parse_line(line: &str) -> Option<(u64, ConnectionEntry)> {
    if let Some(rest) = line.split_once("Connected to ").map(|(_, rest)| rest) {
        let (id, rest) = rest.split_once("/'")?;
        let node_id = id.trim().parse().ok()?;
        let (_, rest) = rest.split_once("' via ")?;
        let via = rest.split_whitespace().next().filter(|s| !s.is_empty());
        return Some((
            node_id,
            ConnectionEntry {
                connected: true,
                via: via.map(str::to_owned),
            },
        ));
    }
    let rest = line
        .split_once("Failed to connect to ")
        .map(|(_, rest)| rest)?;
    let (id, _) = rest.split_once("/'")?;
    Some((
        id.trim().parse().ok()?,
        ConnectionEntry {
            connected: false,
            via: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_connection_log_lines() {
        let (_, connected) =
            parse_line("2026.10.25 12:00:00.000 INFO Connected to 42/'PC' via UDP/outgoing")
                .unwrap();
        assert!(connected.connected);
        assert_eq!(connected.via.as_deref(), Some("UDP/outgoing"));
        let (_, failed) =
            parse_line("2026.10.25 12:00:00.000 WARNING Failed to connect to 43/'PC' (error: 1)")
                .unwrap();
        assert!(!failed.connected);
    }
}
