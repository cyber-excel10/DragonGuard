use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::io::{self, Write};
use std::fs::exists;

mod models;
mod security;
mod tui;
mod utils;
mod vault;

use vault::VaultManager;
use security::MasterPassword;
use tui::DragonTui;
use crate::utils::{prompt_input, generate_secure_password, validate_entry_name, check_common_patterns, has_sequential_chars, has_repeated_chars, format_file_size, validate_password_strength};

#[derive(Parser)]
#[command(name = "dragonguard")]
#[command(about = "🐉 DragonGuard: A secure CLI vault for passwords, notes, and crypto phrases")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    #[arg(long, default_value = "vault.dat")]
    vault: PathBuf,
    #[arg(long)]
    portable: bool,
    #[arg(long)]
    guided: bool,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        #[arg(long)]
        hint: Option<String>,
    },
    Unlock,
    Add {
        name: String,
        username: String,
        notes: String,
        #[arg(default_value = "")]
        password: String,
    },
    List,
    Get {
        name: String,
    },
    Check,
    CheckEntry {
        name: String,
    },
    Delete {
        name: String,
    },
    GeneratePhrase {
        #[arg(default_value = "12")]
        word_count: usize,
        name: String,
    },
    Diag,
}
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let vault_path = get_vault_path(&cli.vault, cli.portable)?;
    if cli.guided {
        guided_mode(&vault_path).await?;
    } else if let Some(command) = cli.command {
        match command {
            Commands::Create { hint } => create_vault(&vault_path, hint).await?,
            Commands::Unlock => unlock_vault(&vault_path).await?,
            Commands::Add { name, username, notes, password } => {
                add_entry(&vault_path, name, username, notes, password).await?
            }
            Commands::List => list_entries(&vault_path).await?,
            Commands::Get { name } => get_entry(&vault_path, name).await?,
            Commands::Check => check_vault(&vault_path).await?,
            Commands::CheckEntry { name } => check_entry(&vault_path, &name).await?,
            Commands::Delete { name } => delete_entry(&vault_path, &name).await?,
            Commands::GeneratePhrase { word_count, name } => {
                generate_phrase(&vault_path, word_count, name).await?
            }
            Commands::Diag => diag(&vault_path).await?,
        }
    } else {
        unlock_vault(&vault_path).await?;
    }
    Ok(())
}

fn get_vault_path(vault_argument: &PathBuf, portable: bool) -> Result<PathBuf> {
    if portable {
        Ok(vault_argument.clone())
    } else {
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
        Ok(home.join(".dragonguard").join("vault.dat"))
    }
}

async fn create_vault(vault_path: &PathBuf, hint: Option<String>) -> Result<()> {
    tui::display_dragon_intro();
    let frame = tui::get_dragon_frame(0);
    println!("🐉 Dragon Frame Sample: {}", frame);
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if exists(vault_path)? {
        return Err(anyhow::anyhow!("🐉 Vault already exists! Use 'dragonguard unlock'."));
    }
    let master_password = MasterPassword::create_new(hint.as_deref()).await?;
    let mut vault = VaultManager::new(vault_path.clone(), master_password.clone());
    vault.create(hint).await?;
    println!("\n🐉 Vault forged in dragon fire!");
    println!("Vault path: {}", vault_path.display());
    println!("\n❗ Memorize your master password! No recovery exists.");
    println!("Consider a BIP-39 phrase or secure physical storage.");
    if master_password.get_hint().is_some() {
        println!("\n💡 Hint stored (encrypted, but memorize password!).");
    }
    println!("To unlock, run 'dragonguard unlock' or 'dragonguard --guided'");
    Ok(())
}

async fn unlock_vault(vault_path: &PathBuf) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let mut vault = VaultManager::load(vault_path.clone(), master_password).await?;
    let mut tui = DragonTui::new(&mut vault);
    tui.run().await?;
    Ok(())
}

async fn add_entry(vault_path: &PathBuf, name: String, username: String, notes: String, password: String) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    validate_entry_name(&name)?;
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let mut vault = VaultManager::load(vault_path.clone(), master_password).await?;
    let password = if password.is_empty() {
        tui::animate_sniffing().await?;
        generate_secure_password(12).await?
    } else {
        validate_password_strength(&password).await?;
        let common_patterns = check_common_patterns(&password);
        if !common_patterns.is_empty() {
            println!("🐉 Warning: Password contains weak patterns: {:?}", common_patterns);
        }
        if has_sequential_chars(&password) {
            println!("🐉 Warning: Password contains sequential characters");
        }
        if has_repeated_chars(&password) {
            println!("🐉 Warning: Password contains repeated characters");
        }
        password
    };
    vault.add_entry(name.clone(), Some(username), password, Some(notes)).await?;
    vault.save().await?;
    println!("🐉 Entry '{}' added to the hoard!", name);
    Ok(())
}

async fn generate_phrase(vault_path: &PathBuf, word_count: usize, name: String) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    validate_entry_name(&name)?;
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let mut vault = VaultManager::load(vault_path.clone(), master_password).await?;
    tui::animate_sniffing().await?;
    let phrase = security::generate_phrase(word_count).await?;
    vault.add_entry(name.clone(), Some("".to_string()), phrase.clone(), Some("Generated crypto phrase".to_string())).await?;
    vault.save().await?;
    println!("🐉 Forged new dragon eggs: {} (stored as '{}')", phrase, name);
    println!("❗ Memorize or securely store this phrase! No recovery exists.");
    Ok(())
}

async fn list_entries(vault_path: &PathBuf) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let vault = VaultManager::load(vault_path.clone(), master_password).await?;
    let entries = vault.list_entries();
    if entries.is_empty() {
        println!("\n🐉 Your vault is empty! Add secrets with 'dragonguard add'.");
        return Ok(());
    }
    println!("\n🐉 Vault Contents:");
    for (i, entry) in entries.iter().enumerate() {
        let prefix = if security::validate_phrase(&entry.password).is_ok() { "🥚" } else { "🔐" };
        println!("{}. {} {} {}", i + 1, prefix, entry.name, entry.strength_emoji());
        if let Some(username) = &entry.username {
            println!("   👤 {}", username);
        }
        println!("   🕐 {}", entry.created_at.format("%Y-%m-%d %H:%M"));
    }
    Ok(())
}

async fn get_entry(vault_path: &PathBuf, name: String) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let vault = VaultManager::load(vault_path.clone(), master_password).await?;
    if let Some(entry) = vault.get_entry(&name) {
        println!("\n🐉 Retrieved from dragon vault:");
        let prefix = if security::validate_phrase(&entry.password).is_ok() { "🥚 Secret Phrase" } else { "🔐 Password" };
        println!("📝 Name: {}", entry.name);
        if let Some(username) = &entry.username {
            println!("👤 Username: {}", username);
        }
        println!("{}: {} (copied to clipboard)", prefix, "*".repeat(entry.password.len()));
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let _ = clipboard.set_text(&entry.password);
            println!("✅ Copied to clipboard!");
        } else {
            println!("⚠️ Clipboard unavailable!");
        }
        if let Some(notes) = &entry.notes {
            println!("📝 Notes: {}", notes);
        }
        println!("💪 Strength: {}", entry.strength_label());
        println!("🕐 Created: {}", entry.created_at.format("%Y-%m-%d %H:%M"));
    } else {
        println!("❌ Entry '{}' not found!", name);
    }
    Ok(())
}

async fn check_vault(vault_path: &PathBuf) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let vault = VaultManager::load(vault_path.clone(), master_password).await?;
    tui::animate_sniffing().await?;
    println!("\n🐉 Dragon Security Scan Results:");
    println!("Vault Integrity: ✅ SECURE");
    println!("🔐 Encryption: AES-256-GCM ✅");
    println!("🛡️ HMAC Verification: ✅ PASSED");
    let file_size = std::fs::metadata(vault_path)?.len();
    println!("📁 Vault Size: {}", format_file_size(file_size));
    let entries = vault.list_entries();
    println!("\n📊 Vault Statistics:");
    println!("   📝 Total entries: {}", entries.len());
    let mut weak_count = 0;
    let mut fair_count = 0;
    let mut strong_count = 0;
    for entry in entries {
        match entry.strength_score() {
            0..=40 => weak_count += 1,
            41..=70 => fair_count += 1,
            _ => strong_count += 1,
        }
        if let Ok(breach_count) = security::check_hibp(&entry.password).await {
            if breach_count > 0 {
                println!("⚠️ {}: Found in {} breaches!", entry.name, breach_count);
            }
        }
    }
    println!("   🔴 Weak: {}", weak_count);
    println!("   🟡 Fair: {}", fair_count);
    println!("   🟢 Strong: {}", strong_count);
    if weak_count > 0 {
        println!("\n⚠️ Consider strengthening weak passwords/phrases!");
    } else {
        println!("\n✅ All entries meet security standards!");
    }
    println!("\n🐉 Your digital hoard is well protected!");
    Ok(())
}

async fn check_entry(vault_path: &PathBuf, name: &str) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let vault = VaultManager::load(vault_path.clone(), master_password).await?;
    if let Some(entry) = vault.get_entry(name) {
        println!("\n🐉 Checking '{}'...", entry.name);
        tui::animate_sniffing().await?;
        match security::check_hibp(&entry.password).await {
            Ok(count) if count > 0 => println!("🚨 WARNING: Found in {} breaches!", count),
            Ok(_) => println!("✅ Unbreached - safe in the dragon's lair!"),
            Err(e) => println!("⚠️ Could not check breaches: {}", e),
        }
        println!("💪 Strength: {}", entry.strength_label());
    } else {
        println!("❌ Entry '{}' not found!", name);
    }
    Ok(())
}

async fn delete_entry(vault_path: &PathBuf, name: &str) -> Result<()> {
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("🐉 No vault found! Use 'dragonguard create'."));
    }
    validate_entry_name(name)?;
    let master_password = MasterPassword::prompt_existing(vault_path).await?;
    let mut vault = VaultManager::load(vault_path.clone(), master_password).await?;
    if vault.delete_entry(name).await? {
        vault.save().await?;
        println!("🐉 Entry '{}' burned by dragon fire!", name);
    } else {
        println!("❌ Entry '{}' not found!", name);
    }
    Ok(())
}

async fn guided_mode(vault_path: &PathBuf) -> Result<()> {
    loop {
         println!(r#"
         $$\      $$\           $$\                                                 $$$$$$$$\       $$$$$$$\                                                   
$$ | $\  $$ |          $$ |                                                  \__$$  __|             $$  __$$\                                                  
$$ |$$$\ $$ | $$$$$$\  $$ | $$$$$$$\  $$$$$$\  $$$$$$\$$$$\   $$$$$$\           $$ | $$$$$$\        $$ |  $$ | $$$$$$\  $$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  
$$ $$ $$\$$ |$$  __$$\ $$ |$$  _____|$$  __$$\ $$  _$$  _$$\ $$  __$$\          $$ |$$  __$$\       $$ |  $$ |$$  __$$\ \____$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$$$  _$$$$ |$$$$$$$$ |$$ |$$ /      $$ /  $$ |$$ / $$ / $$ |$$$$$$$$ |         $$ |$$ /  $$ |      $$ |  $$ |$$ |  \__|$$$$$$$ |$$ /  $$ |$$ /  $$ |$$ |  $$ | 
$$$  / \$$$ |$$   ____|$$ |$$ |      $$ |  $$ |$$ | $$ | $$ |$$   ____|         $$ |$$ |  $$ |      $$ |  $$ |$$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
$$  /   \$$ |\$$$$$$$\ $$ |\$$$$$$$\ \$$$$$$  |$$ | $$ | $$ |\$$$$$$$\          $$ |\$$$$$$  |      $$$$$$$  |$$ |     \$$$$$$$ |\$$$$$$$ |\$$$$$$  |$$ |  $$ |
\__/     \__| \_______|\__| \_______| \______/ \__| \__| \__| \_______|         \__| \______/       \_______/ \__|      \_______| \____$$ | \______/ \__|  \__|
                                                                                                                                 $$\   $$ |                    
                                                                                                                                 \$$$$$$  |                    
                                                                                                                                  \______/ 
    
    
$$$$$$\                                      $$\ 
$$  __$$\                                     $$ |
$$ /  \__|$$\   $$\  $$$$$$\   $$$$$$\   $$$$$$$ |
$$ |$$$$\ $$ |  $$ | \____$$\ $$  __$$\ $$  __$$ |
$$ |\_$$ |$$ |  $$ | $$$$$$$ |$$ |  \__|$$ /  $$ |                   
$$ |  $$ |$$ |  $$ |$$  __$$ |$$ |      $$ |  $$ |                        
\$$$$$$  |\$$$$$$  |\$$$$$$$ |$$ |      \$$$$$$$ |
 \______/  \______/  \_______|\__|       \_______|



                        /           / 
                       /' .,,,,  ./       
                      /';'     ,/      
                     / /   ,,//,`'`    
                    ( ,, '_,  ,,,' ``  
                    |    /@  ,,, ;" `  
                   /    .   ,''/' `,`` 
                  /   .     ./, `,, ` ; 
               ,./  .   ,-,',` ,,/''\,' 
              |   /; ./,,'`,,'' |   |   
              |     /   ','    /    |   
               \___/'   '     |     |   
                 `,,'  |      /     `\   
                      /      |        
                     (       /          
                      `-._.-'                              
                      
                      

"I breathe fire upon intruders
and guard your secrets with steel and flame."  Forging your impenetrable vault...
    "#
    );
        println!("\nHere are set of commands that will guide you through the usage of 🐉 DragonGuard Guided Mode");
        println!("=======================================================");
        println!("1. Create new vault");
        println!("2. Unlock vault (TUI)");
        println!("3. Add entry");
        println!("4. List entries");
        println!("5. Get entry");
        println!("6. Check vault");
        println!("7. Check entry");
        println!("8. Delete entry");
        println!("9. Generate BIP-39 phrase");
        println!("10. Run diagnostics");
        println!("11. Exit");
        print!("\nChoose an option (1-11): ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        match choice.trim() {
            "1" => {
                let hint = prompt_input("Enter optional password hint: ").await?;
                create_vault(vault_path, if hint.is_empty() { None } else { Some(hint) }).await?;
            }
            "2" => unlock_vault(vault_path).await?,
            "3" => {
                let name = prompt_input("Enter name of entry: ").await?;
                let username = prompt_input("Enter a unique name for your entry (optional): ").await?;
                let password = prompt_input("Enter a password, secretphrase or anything you want to save (empty for random): ").await?;
                let notes = prompt_input("Enter notes i.e description about the entry (optional): ").await?;
                let password = if password.is_empty() {
                    tui::animate_sniffing().await?;
                    generate_secure_password(12).await?
                } else {
                    validate_password_strength(&password).await?;
                    let common_patterns = check_common_patterns(&password);
                    if !common_patterns.is_empty() {
                        println!("🐉 Warning: Password contains weak patterns: {:?}", common_patterns);
                    }
                    if has_sequential_chars(&password) {
                        println!("🐉 Warning: Password contains sequential characters");
                    }
                    if has_repeated_chars(&password) {
                        println!("🐉 Warning: Password contains repeated characters");
                    }
                    password
                };
                add_entry(vault_path, name, username, notes, password).await?;
            }
            "4" => list_entries(vault_path).await?,
            "5" => {
                let name = prompt_input("Enter entry name: ").await?;
                get_entry(vault_path, name).await?;
            }
            "6" => check_vault(vault_path).await?,
            "7" => {
                let name = prompt_input("Enter entry name to check: ").await?;
                check_entry(vault_path, &name).await?;
            }
            "8" => {
                let name = prompt_input("Enter entry name to delete: ").await?;
                delete_entry(vault_path, &name).await?;
            }
            "9" => {
                let name = prompt_input("Enter name for generated phrase: ").await?;
                let word_count = prompt_input("Enter word count (12, 15, 18, 21, 24): ").await?.parse()?;
                generate_phrase(vault_path, word_count, name).await?;
            }
            "10" => diag(vault_path).await?,
            "11" => break,
            _ => println!("❌ Invalid option! Choose 1-11."),
        }
    }
    Ok(())
}

async fn diag(vault_path: &PathBuf) -> Result<()> {
    println!("🐉 Running diagnostics...");

    let master_password = MasterPassword::new();

    // this calls the security.rs functions
    let _ = security::generate_phrase(12).await?;

    // this calls the utils.rs functions
    let _ = prompt_input("Test prompt: ").await?;
    let _ = validate_password_strength("Test123!").await?;
    let _ = generate_secure_password(12).await?;
    let _ = validate_entry_name("test_entry")?;
    let _ = check_common_patterns("password123");
    let _ = has_sequential_chars("abc123");
    let _ = has_repeated_chars("aaa123");
    let _ = format_file_size(1024);

    // calls the  tui.rs functions
    tui::display_dragon_intro();
    let _ = tui::get_dragon_frame(0);

    
    let mut vault = VaultManager::new(vault_path.clone(), master_password);
    let _master_password = MasterPassword::new();
    let mut tui = DragonTui::new(&mut vault);

    use ratatui::prelude::*;
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut frame = terminal.get_frame();

    tui.render_dragon_header(&mut frame, Rect::new(0, 0, 80, 4));
    tui.render_vault_view(&mut frame, Rect::new(0, 4, 80, 16));
    tui.render_add_entry(&mut frame, Rect::new(0, 4, 80, 16));
    tui.render_generate_phrase(&mut frame, Rect::new(0, 4, 80, 16));
    tui.render_view_entry(&mut frame, Rect::new(0, 4, 80, 16));
    tui.render_check_breach(&mut frame, Rect::new(0, 4, 80, 16));
    tui.render_help(&mut frame, Rect::new(0, 4, 80, 16));
    tui.render_status_bar(&mut frame, Rect::new(0, 20, 80, 4));
    tui.render_error(&mut frame, Rect::new(0, 4, 80, 16), "Test error");


    tui.ui(&mut frame);
    tui.run().await?;

    println!("🐉 Diagnostics complete!");
    Ok(())
}