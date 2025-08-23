use anyhow::Result;
use std::io::{self, Write};
use rand::seq::SliceRandom;
use tokio::task;

use chrono::DateTime;
use chrono::Utc;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct VaultEntry {
    id: String,
    pub name: String,
    pub secret: String,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultConfig {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub hint: Option<String>,
    pub iterations: u32,
}

impl Default for VaultConfig {
    fn default() -> Self {
        VaultConfig {
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

pub async fn prompt_input(prompt: &str) -> Result<String> {
    let prompt = prompt.to_string(); 
    task::spawn_blocking(move || {
        print!("{}", prompt);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    })
    .await?
}

pub async fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(anyhow::anyhow!("🐉 Password too weak for a dragon! Use at least 8 characters."));
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_lowercase() { has_lower = true; }
        if c.is_uppercase() { has_upper = true; }
        if c.is_numeric() { has_digit = true; }
        if !c.is_alphanumeric() { has_special = true; }
    }

    let criteria_met = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if criteria_met < 3 {
        return Err(anyhow::anyhow!(
            "🐉 Password needs more dragon fire! Include at least 3 of: lowercase, uppercase, numbers, special characters."
        ));
    }

    let common_patterns = check_common_patterns(password);
    if !common_patterns.is_empty() {
        return Err(anyhow::anyhow!("🐉 Password contains weak patterns: {:?}", common_patterns));
    }

    if has_sequential_chars(password) {
        return Err(anyhow::anyhow!("🐉 Password contains sequential characters (e.g., abc, 123)"));
    }

    if has_repeated_chars(password) {
        return Err(anyhow::anyhow!("🐉 Password contains too many repeated characters"));
    }

    crate::tui::animate_sniffing().await?;
    if let Ok(count) = crate::security::check_hibp(password).await {
        if count > 0 {
            return Err(anyhow::anyhow!(
                "🚨 Password found in {} breaches! Choose a stronger one.", count
            ));
        }
    }

    Ok(())
}

pub fn check_common_patterns(password: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let lower_pwd = password.to_lowercase();

    let weak_patterns = [
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "secret",
        "login", "12345678", "abc123", "pass123", "user123",
    ];

    for pattern in &weak_patterns {
        if lower_pwd.contains(pattern) {
            warnings.push(format!("Contains weak pattern: {}", pattern));
        }
    }

    warnings
}

pub fn has_sequential_chars(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    for window_size in 3..=4 {
        for window in chars.windows(window_size) {
            let is_sequential = window.iter().enumerate().all(|(i, &c)| {
                if i == 0 { true } else {
                    let prev = window[i - 1] as u8;
                    let curr = c as u8;
                    curr == prev + 1 || curr == prev - 1
                }
            });
            if is_sequential {
                return true;
            }
        }
    }

    let keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "123456"];
    keyboard_patterns.iter().any(|&pattern| password.to_lowercase().contains(pattern))
}

pub fn has_repeated_chars(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    for window in chars.windows(3) {
        if window[0] == window[1] && window[1] == window[2] {
            return true;
        }
    }
    false
}

pub async fn generate_secure_password(length: usize) -> Result<String> {
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let mut rng = rand::thread_rng();
    let mut password = String::new();
    while password.len() < length {
        password = (0..length)
            .map(|_| chars.choose(&mut rng).map(|&c| c as char).unwrap_or('?'))
            .collect();
        if validate_password_strength(&password).await.is_ok() {
            return Ok(password);
        }
        password.clear();
    }
    Err(anyhow::anyhow!("🐉 Failed to generate a secure password!"))
}

pub fn validate_entry_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow::anyhow!("🐉 Entry name cannot be empty!"));
    }
    if name.len() > 100 {
        return Err(anyhow::anyhow!("🐉 Entry name too long (max 100 characters)!"));
    }
    let invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|'];
    if name.chars().any(|c| invalid_chars.contains(&c)) {
        return Err(anyhow::anyhow!("🐉 Entry name contains invalid characters!"));
    }
    Ok(())
}

pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("🐉 {} {}", bytes, UNITS[unit_index])
    } else {
        format!("🐉 {:.1} {}", size, UNITS[unit_index])
    }
}