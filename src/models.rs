use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub hint: Option<String>,
    pub iterations: u32,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            hint: None,
            iterations: 100_000,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    pub config: VaultConfig,
    pub entries: Vec<VaultEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub data: Vec<u8>,
    pub hmac: Vec<u8>,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

impl VaultEntry {
    pub fn new(name: String, username: Option<String>, password: String, notes: Option<String>) -> Self {
        let moment = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            username,
            password: password.clone(),
            notes,
            created_at: moment,
            updated_at: moment,
            tags: if crate::security::validate_phrase(&password).is_ok() {
                vec!["crypto".to_string()]
            } else {
                vec![]
            },
        }
    }

    pub fn strength_score(&self) -> u8 {
        let is_phrase = crate::security::validate_phrase(&self.password).is_ok();
        if is_phrase {
            let word_count = self.password.split_whitespace().count() as f64;
            let entropy = (word_count * 2048_f64.log2()).round() as u8;
            (entropy as f64 / 1.4).min(100.0) as u8
        } else {
            let mut score = 0;
            let pass = &self.password;
            if pass.len() >= 8 { score += 20; }
            if pass.len() >= 12 { score += 20; }
            if pass.len() >= 16 { score += 10; }
            if pass.chars().any(|c| c.is_lowercase()) { score += 15; }
            if pass.chars().any(|c| c.is_uppercase()) { score += 15; }
            if pass.chars().any(|c| c.is_numeric()) { score += 10; }
            if pass.chars().any(|c| !c.is_alphanumeric()) { score += 10; }
            score.min(100)
        }
    }

    pub fn strength_label(&self) -> &'static str {
        match self.strength_score() {
            0..=40 => "🔴 Weak",
            41..=70 => "🟡 Fair",
            71..=90 => "🟢 Strong",
            _ => "🟢 Excellent",
        }
    }

    pub fn strength_emoji(&self) -> &'static str {
        match self.strength_score() {
            0..=40 => "🔴",
            41..=70 => "🟡",
            _ => "🟢",
        }
    }
}
