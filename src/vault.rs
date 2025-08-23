use crate::models::{VaultEntry, VaultConfig, VaultData, EncryptedVault};
use crate::security::MasterPassword;
use anyhow::Result;
use std::path::PathBuf;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::Argon2;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub struct VaultManager {
    path: PathBuf,
    data: VaultData,
    master_password: MasterPassword,
}

impl VaultManager {
    pub fn new(path: PathBuf, master_password: MasterPassword) -> Self {
        Self {
            path,
            data: VaultData {
                config: VaultConfig::default(),
                entries: vec![],
            },
            master_password,
        }
    }

    pub async fn create(&mut self, hint: Option<String>) -> Result<()> {
        self.data.entries.clear();
        self.data.config = VaultConfig {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            hint,
            iterations: 100_000,
        };
        self.save().await?;
        Ok(())
    }

    pub async fn load(path: PathBuf, master_password: MasterPassword) -> Result<Self> {
        let vault_bytes = std::fs::read(&path)?;
        let encrypted_vault: EncryptedVault = serde_json::from_slice(&vault_bytes)?;
        verify_hmac(&encrypted_vault.data, &encrypted_vault.hmac, master_password.get_password())?;
        let crypto = CryptoManager::new(master_password.get_password(), &encrypted_vault.salt)?;
        let decrypted_data = crypto.decrypt(&encrypted_vault.data, &encrypted_vault.nonce)?;
        let data: VaultData = serde_json::from_slice(&decrypted_data)?;
        Ok(Self { path, data, master_password })
    }

    pub async fn save(&self) -> Result<()> {
        let json_data = serde_json::to_vec(&self.data)?;
        let salt = generate_salt();
        let crypto = CryptoManager::new(self.master_password.get_password(), &salt)?;
        let (encrypted_data, nonce) = crypto.encrypt(&json_data)?;
        let hmac = calculate_hmac(&encrypted_data, self.master_password.get_password())?;
        let encrypted_vault = EncryptedVault {
            salt,
            nonce,
            data: encrypted_data,
            hmac,
            version: 1,
        };
        let vault_bytes = serde_json::to_vec(&encrypted_vault)?;
        std::fs::write(&self.path, vault_bytes).map_err(|e| anyhow::anyhow!("Failed to save vault: {}", e))?;
        Ok(())
    }

    pub async fn add_entry(&mut self, name: String, username: Option<String>, password: String, notes: Option<String>) -> Result<()> {
        let entry = VaultEntry::new(name, username, password, notes);
        self.data.entries.push(entry);
        self.data.config.updated_at = chrono::Utc::now();
        self.save().await?;
        Ok(())
    }

    pub async fn delete_entry(&mut self, id: &str) -> Result<bool> {
        let initial_len = self.data.entries.len();
        self.data.entries.retain(|e| e.id != id);
        if self.data.entries.len() < initial_len {
            self.data.config.updated_at = chrono::Utc::now();
            self.save().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn list_entries(&self) -> &[VaultEntry] {
        &self.data.entries
    }

    pub fn get_entry(&self, id: &str) -> Option<&VaultEntry> {
        self.data.entries.iter().find(|e| e.id == id)
    }

    pub fn get_hint(&self) -> Option<&String> {
        self.data.config.hint.as_ref()
    }
}

struct CryptoManager {
    cipher: Aes256Gcm,
}

impl CryptoManager {
    fn new(master_password: &str, salt: &[u8]) -> Result<Self> {
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(master_password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();
        Ok(Self { cipher })
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        Ok((ciphertext, nonce_bytes))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed - wrong password or corrupted vault"))
    }
}

fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn calculate_hmac(data: &[u8], key: &str) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_hmac(data: &[u8], expected_hmac: &[u8], key: &str) -> Result<()> {
    let calculated_hmac = calculate_hmac(data, key)?;
    if calculated_hmac != expected_hmac {
        return Err(anyhow::anyhow!("🚨 Vault integrity check FAILED! File may be corrupted or tampered with."));
    }
    Ok(())
}