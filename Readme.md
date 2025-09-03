# 🐉 DragonGuard – Password Manager

DragonGuard is a secure, Rust-based password manager with a focus on safety, simplicity, and privacy.  
The project is still under active development — releases are not yet finalized.

## 🚧 Project Status
⚠️ This project is **in development**.  
- Source code is available.  
- Releases are being prepared but **not yet stable or fully functional**.  
- Contributions, feedback, and suggestions are welcome!

---

## 📖 Features (Planned / In Progress)
- 🔑 Secure password storage  
- 🔒 Strong encryption  
- 🖥️ Cross-platform builds (Linux, macOS, Windows)  
- 🐉 TUI (Terminal User Interface)  
- 📂 Encrypted vault system  
- 📊 Security tools and phrase generator 

---

## 📚 Documentation
For usage details and future examples, check the [docs/USAGE.md](docs/USAGE.md) file.  
*(Please note: instructions may not yet reflect a fully working build.)*

---


## 🛠️ Installation
Currently, you can clone the repo to explore the source code:

git clone https://github.com/cyber-excel10/DragonGuard/git

cd dragonguard

cargo build

## 📂 Project Structure
```bash

├── Cargo.toml                 # Dependencies
├── README.md                  # Overview, setup, security notes
├── LICENSE                    # MIT license
├── .gitignore                 # Rust defaults
├── releases/                  # Pre-built binaries + checksums
├── docs/
│   └── USAGE.md               # Non-tech user guide
├── src/
│   ├── main.rs                # CLI entry (clap)
│   ├── lib.rs                 # Exports
│   ├── vault.rs               # Vault logic (crypto, HMAC)
│   ├── security.rs            # Password checks, HIBP, mnemonics
│   ├── tui.rs                 # Dragon TUI animations & UI
│   ├── models.rs              # VaultEntry struct
│   └── utils.rs               # Helpers & validation
├── tests/
│   └── vault_tests.rs         # Vault unit tests
└── scripts/
    └── build_releases.sh      # Binary build script




