use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    pub dark: bool,
    pub refresh_seconds: u64,
    pub favorites: HashSet<String>,
    pub compact: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            dark: false,
            refresh_seconds: 10,
            favorites: HashSet::new(),
            compact: false,
        }
    }
}

fn directory() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
        .unwrap_or_else(std::env::temp_dir)
        .join("RvpnKit")
}

impl Preferences {
    pub fn load() -> Self {
        let mut result: Self = std::fs::read_to_string(directory().join("preferences.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| Self {
                dark: std::fs::read_to_string(directory().join("ui.conf"))
                    .is_ok_and(|s| s.trim() == "dark"),
                ..Self::default()
            });
        if ![0, 5, 10, 30].contains(&result.refresh_seconds) {
            result.refresh_seconds = 10;
        }
        result
    }
    pub fn save(&self) -> Result<(), String> {
        let path = directory();
        std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path.join("preferences.json"), bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_settings_get_safe_defaults() {
        let settings: Preferences = serde_json::from_str(r#"{"dark":true}"#).unwrap();
        assert!(settings.dark);
        assert_eq!(settings.refresh_seconds, 10);
        assert!(settings.favorites.is_empty());
    }
    #[test]
    fn favorite_settings_round_trip() {
        let mut settings = Preferences::default();
        settings
            .favorites
            .insert("00112233445566778899aabbccddeeff".into());
        let restored: Preferences =
            serde_json::from_str(&serde_json::to_string(&settings).unwrap()).unwrap();
        assert_eq!(restored.favorites, settings.favorites);
    }
}
