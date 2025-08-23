use anyhow::Result;
use sha1::{Sha1, Digest};
use reqwest::Client; 
use bip39::Language;
use rand::{rngs::OsRng, Rng};
use zeroize::ZeroizeOnDrop;
use std::path::PathBuf;
use crate::utils::prompt_input;

#[derive(ZeroizeOnDrop, Clone)]
pub struct MasterPassword {
    password: String,
    hint: Option<String>,
}

impl MasterPassword {
    pub async fn create_new(hint: Option<&str>) -> Result<Self> {
        println!("🔐 Forging a master key for your dragon vault...\n");
        if hint.is_none() {
            display_mnemonic_suggestion();
        }
        let password = loop {
            let password = prompt_input("🐉 Enter master password (hidden): ").await?;
            if password.len() < 8 {
                println!("❌ Password too short! Dragons demand at least 8 characters.");
                continue;
            }
            let confirm = prompt_input("🐉 Confirm master password: ").await?;
            if password != confirm {
                println!("❌ Passwords don't match! Try again, young dragon.");
                continue;
            }
            println!("🔍 Dragon sniffing for breaches...");
            crate::tui::animate_sniffing().await?;
            match check_hibp(&password).await {
                Ok(count) if count > 0 => {
                    println!("🚨 WARNING: Password found in {} breaches!", count);
                    println!("   Forge a new password worthy of a dragon's hoard!");
                    continue;
                }
                Ok(_) => {
                    println!("✅ Password is unbreached - a true dragon's secret!");
                    break password;
                }
                Err(e) => {
                    println!("⚠️ Could not check breaches ({}), but proceeding...", e);
                    break password;
                }
            }
        };
        if hint.is_some() {
            println!("💡 Hint will be stored encrypted, but guard your password like a dragon!");
        }
        Ok(Self {
            password,
            hint: hint.map(String::from),
        })
    }

    pub async fn prompt_existing(vault_path: &PathBuf) -> Result<Self> {
        if let Ok(config) = load_vault_config(vault_path) {
            if let Some(hint) = &config.hint {
                println!("💡 Dragon's hint: {}", hint);
            }
        }
        let password = prompt_input("🐉 Enter master password (hidden): ").await?;
        Ok(Self {
            password,
            hint: None,
        })
    }

    pub fn new() -> Self {
        Self {
            password: String::new(),
            hint: None,
        }
    }

    pub fn get_password(&self) -> &str {
        &self.password
    }

    pub fn get_hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }
}

pub async fn check_hibp(password: &str) -> Result<u32> {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash_hex = hasher.finalize().iter().map(|b| format!("{:02X}", b)).collect::<String>();
    let prefix = &hash_hex[0..5];
    let suffix = &hash_hex[5..];
    let client = Client::new();
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let resp = client
        .get(&url)
        .header("User-Agent", "DragonGuard")
        .send()
        .await?;
    let body = resp.text().await?;
    for line in body.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 && parts[0].eq_ignore_ascii_case(suffix) {
            return Ok(parts[1].parse::<u32>().unwrap_or(0));
        }
    }
    Ok(0)
}

pub fn validate_phrase(phrase: &str) -> Result<()> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err(anyhow::anyhow!("🐉 Invalid BIP-39 phrase length! Use 12, 15, 18, 21, or 24 words."));
    }
    let dict = Language::English.word_list();
    if words.iter().all(|w| dict.contains(w)) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("🐉 Invalid BIP-39 secret phrase!"))
    }
}

pub async fn generate_phrase(word_count: usize) -> Result<String> {
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(anyhow::anyhow!("🐉 Word count must be 12, 15, 18, 21, or 24"));
    }
    let dict = Language::English.word_list();
    let mut rng = OsRng;
    let mut words = vec![];
    for _ in 0..word_count {
        let idx = rng.gen_range(0..2048);
        words.push(dict[idx]);
    }
    let phrase = words.join(" ");
    validate_phrase(&phrase)?;
    crate::tui::animate_sniffing().await?;
    println!("🐉 Forged dragon eggs!");
    Ok(phrase)
}

fn display_mnemonic_suggestion() {
    println!("💡 TIP: Forge a BIP-39 passphrase for your dragon vault:");
    println!("   Example: {}", suggest_mnemonic_phrase());
    println!("   These are as secure as dragon scales and easier to remember!\n");
}

fn suggest_mnemonic_phrase() -> String {
    let dict = Language::English.word_list();
    let mut rng = rand::thread_rng();
    let mut words = vec![];
    for _ in 0..12 {
        let idx = rng.gen_range(0..2048);
        words.push(dict[idx]);
    }
    words.join(" ")
}

fn load_vault_config(vault_path: &PathBuf) -> Result<crate::models::VaultConfig> {
    if !vault_path.exists() { // Mock Frame and Rect for rendering methods
        return Ok(crate::models::VaultConfig::default());
    }
    Ok(crate::models::VaultConfig {
        version: "1.0".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        hint: None,
        iterations: 100_000,
    })
}