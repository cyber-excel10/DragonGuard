use crate::{security, utils, vault::VaultManager};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::{self, Write};

#[derive(PartialEq)]
enum AppState {
    Welcome,
    VaultView,
    AddEntry,
    GeneratePhrase,
    ViewEntry,
    CheckBreach,
    Help,
    Error(String),
}

#[derive(PartialEq)]
enum InputField {
    Name,
    Username,
    Password,
    Notes,
    PhraseName,
    PhraseWordCount,
}

pub struct DragonTui<'a> {
    vault: &'a mut VaultManager,
    state: AppState,
    list_state: ListState,
    selected_entry: Option<usize>,
    input_buffer: String,
    input_field: InputField,
    dragon_frame: usize,
    add_entry_data: (String, Option<String>, String, Option<String>), // (name, username, password, notes)
    phrase_data: (String, usize),
}

impl<'a> DragonTui<'a> {
    pub fn new(vault: &'a mut VaultManager) -> Self {
        let is_empty = vault.list_entries().is_empty();
        let state = if is_empty { AppState::Welcome } else { AppState::VaultView };
        let mut list_state = ListState::default();
        if !is_empty {
            list_state.select(Some(0));
        }
        Self {
            vault,
            state,
            list_state,
            selected_entry: None,
            input_buffer: String::new(),
            input_field: InputField::Name,
            dragon_frame: 0,
            add_entry_data: (String::new(), None, String::new(), None),
            phrase_data: (String::new(), 12),
        }
    }
    pub async fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        let result = self.run_app(&mut terminal).await;
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;
        result
    }

    pub async fn run_app<B: ratatui::backend::Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            terminal.draw(|f| self.ui(f))?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match self.state {
                    AppState::Welcome => {
                        match key.code {
                            KeyCode::Enter => self.state = AppState::VaultView,
                            KeyCode::Char('h') => self.state = AppState::Help,
                            _ => {}
                        }
                    }
                    AppState::VaultView => {
                        match key.code {
                            KeyCode::Char('q') => break,
                            KeyCode::Char('a') => {
                                self.state = AppState::AddEntry;
                                self.input_field = InputField::Name;
                                self.input_buffer.clear();
                                self.add_entry_data = (String::new(), None, String::new(), None);
                            }
                            KeyCode::Char('g') => {
                                self.state = AppState::GeneratePhrase;
                                self.input_field = InputField::PhraseName;
                                self.input_buffer.clear();
                                self.phrase_data = (String::new(), 12);
                            }
                            KeyCode::Char('b') => self.state = AppState::CheckBreach,
                            KeyCode::Char('h') => self.state = AppState::Help,
                            KeyCode::Enter => {
                                if let Some(selected) = self.list_state.selected() {
                                    self.selected_entry = Some(selected);
                                    self.state = AppState::ViewEntry;
                                }
                            }
                            KeyCode::Up | KeyCode::Down => {
                                let len = self.vault.list_entries().len();
                                let i = match self.list_state.selected() {
                                    Some(i) => if key.code == KeyCode::Up {
                                        if i == 0 { len - 1 } else { i - 1 }
                                    } else {
                                        if i >= len - 1 { 0 } else { i + 1 }
                                    },
                                    None => 0,
                                };
                                self.list_state.select(Some(i));
                            }
                            KeyCode::Delete => {
                                if let Some(selected) = self.list_state.selected() {
                                    if let Some(entry) = self.vault.list_entries().get(selected) {
                                        let id = entry.id.clone();
                                        if self.vault.delete_entry(&id).await? {
                                            self.vault.save().await?;
                                            self.state = AppState::Error(format!("🐉 Entry '{}' burned!", id));
                                            let len = self.vault.list_entries().len();
                                            if len == 0 {
                                                self.list_state.select(None);
                                            } else if selected >= len {
                                                self.list_state.select(Some(len - 1));
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    AppState::AddEntry => {
                        match key.code {
                            KeyCode::Esc => {
                                self.state = AppState::VaultView;
                                self.input_buffer.clear();
                                self.input_field = InputField::Name;
                            }
                            KeyCode::Enter => {
                                match self.input_field {
                                    InputField::Name => {
                                        if let Err(e) = utils::validate_entry_name(&self.input_buffer) {
                                            self.state = AppState::Error(e.to_string());
                                        } else {
                                            self.add_entry_data.0 = self.input_buffer.clone();
                                            self.input_buffer.clear();
                                            self.input_field = InputField::Username;
                                        }
                                    }
                                    InputField::Username => {
                                        self.add_entry_data.1 = if self.input_buffer.is_empty() { None } else { Some(self.input_buffer.clone()) };
                                        self.input_buffer.clear();
                                        self.input_field = InputField::Password;
                                    }
                                    InputField::Password => {
                                        let password = if self.input_buffer.is_empty() {
                                            utils::generate_secure_password(12).await?
                                        } else {
                                            self.input_buffer.clone()
                                        };
                                        self.add_entry_data.2 = password;
                                        self.input_buffer.clear();
                                        self.input_field = InputField::Notes;
                                    }
                                    InputField::Notes => {
                                        self.add_entry_data.3 = if self.input_buffer.is_empty() { None } else { Some(self.input_buffer.clone()) };
                                        self.vault.add_entry(self.add_entry_data.0.clone(), self.add_entry_data.1.clone(), self.add_entry_data.2.clone(), self.add_entry_data.3.clone()).await?;
                                        self.vault.save().await?;
                                        self.state = AppState::Error(format!("🐉 Entry '{}' added!", self.add_entry_data.0));
                                        self.input_buffer.clear();
                                        self.input_field = InputField::Name;
                                        self.list_state.select(Some(self.vault.list_entries().len() - 1));
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Char(c) => self.input_buffer.push(c),
                            KeyCode::Backspace => { self.input_buffer.pop(); }
                            _ => {}
                        }
                    }
                    AppState::GeneratePhrase => {
                        match key.code {
                            KeyCode::Esc => {
                                self.state = AppState::VaultView;
                                self.input_buffer.clear();
                                self.input_field = InputField::PhraseName;
                            }
                            KeyCode::Enter => {
                                match self.input_field {
                                    InputField::PhraseName => {
                                        if let Err(e) = utils::validate_entry_name(&self.input_buffer) {
                                            self.state = AppState::Error(e.to_string());
                                        } else {
                                            self.phrase_data.0 = self.input_buffer.clone();
                                            self.input_buffer.clear();
                                            self.input_field = InputField::PhraseWordCount;
                                        }
                                    }
                                    InputField::PhraseWordCount => {
                                        if let Ok(word_count) = self.input_buffer.parse::<usize>() {
                                            if [12, 15, 18, 21, 24].contains(&word_count) {
                                                self.phrase_data.1 = word_count;
                                                let phrase = security::generate_phrase(word_count).await?;
                                                self.vault.add_entry(self.phrase_data.0.clone(), None, phrase.clone(), None).await?;
                                                self.vault.save().await?;
                                                self.state = AppState::Error(format!("🐉 Phrase '{}' generated!", self.phrase_data.0));
                                                self.input_buffer.clear();
                                                self.input_field = InputField::PhraseName;
                                                self.list_state.select(Some(self.vault.list_entries().len() - 1));
                                            } else {
                                                self.state = AppState::Error("❌ Word count must be 12, 15, 18, 21, or 24!".to_string());
                                            }
                                        } else {
                                            self.state = AppState::Error("❌ Invalid word count!".to_string());
                                        }
                                        self.input_buffer.clear();
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Char(c) => self.input_buffer.push(c),
                            KeyCode::Backspace => { self.input_buffer.pop(); }
                            _ => {}
                        }
                    }
                    AppState::ViewEntry => {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                self.state = AppState::VaultView;
                                self.selected_entry = None;
                            }
                            KeyCode::Char('c') => {
                                if let Some(selected) = self.selected_entry {
                                    if let Some(entry) = self.vault.list_entries().get(selected) {
                                        use arboard::Clipboard;
                                        if let Ok(mut clipboard) = Clipboard::new() {
                                            if clipboard.set_text(&entry.password).is_ok() {
                                                self.state = AppState::Error("🐉 Password copied to clipboard!".to_string());
                                            } else {
                                                self.state = AppState::Error("❌ Failed to copy password!".to_string());
                                            }
                                        } else {
                                            self.state = AppState::Error("❌ Clipboard unavailable!".to_string());
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    AppState::CheckBreach => {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => self.state = AppState::VaultView,
                            KeyCode::Enter => {
                                if let Some(selected) = self.list_state.selected() {
                                    if let Some(entry) = self.vault.list_entries().get(selected) {
                                        animate_sniffing().await?;
                                        match security::check_hibp(&entry.password).await {
                                            Ok(count) if count > 0 => {
                                                self.state = AppState::Error(format!("🚨 WARNING: '{}' found in {} breaches!", entry.name, count));
                                            }
                                            Ok(_) => {
                                                self.state = AppState::Error(format!("✅ '{}' is unbreached - safe in the dragon's lair!", entry.name));
                                            }
                                            Err(e) => {
                                                self.state = AppState::Error(format!("⚠️ Could not check breaches for '{}': {}", entry.name, e));
                                            }
                                        }
                                    } else {
                                        self.state = AppState::Error("❌ No entry selected!".to_string());
                                    }
                                } else {
                                    self.state = AppState::Error("❌ No entry selected!".to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                    AppState::Help => {
                        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::F(1)) {
                            self.state = AppState::VaultView;
                        }
                    }
                    AppState::Error(_) => {
                        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter) {
                            self.state = AppState::VaultView;
                        }
                    }
                }
            }
            self.dragon_frame = (self.dragon_frame + 1) % 4;
        }
        Ok(())
    }

    pub fn ui(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Percentage(75),
                Constraint::Length(3),
            ])
            .split(f.size());

        self.render_dragon_header(f, chunks[0]);
        match &self.state {
            AppState::Welcome => self.render_welcome(f, chunks[1]),
            AppState::VaultView => self.render_vault_view(f, chunks[1]),
            AppState::AddEntry => self.render_add_entry(f, chunks[1]),
            AppState::GeneratePhrase => self.render_generate_phrase(f, chunks[1]),
            AppState::ViewEntry => self.render_view_entry(f, chunks[1]),
            AppState::CheckBreach => self.render_check_breach(f, chunks[1]),
            AppState::Help => self.render_help(f, chunks[1]),
            AppState::Error(msg) => self.render_error(f, chunks[1], msg),
        }
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_welcome(&self, f: &mut Frame, area: Rect) {
        let welcome = Paragraph::new(
            "🐉 Welcome to DragonGuard!\n\n\
             Your secure vault for secrets and crypto phrases.\n\n\
             Press Enter to start or 'h' for help."
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("🏠 Welcome to Your Dragon Lair")
                .style(Style::default().fg(Color::Green)),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });
        f.render_widget(Clear, area);
        f.render_widget(welcome, area);
    }

    pub fn render_dragon_header(&self, f: &mut Frame, area: Rect) {
        let dragon_art = get_dragon_frame(self.dragon_frame);
        let hint = self.vault.get_hint().map(|h| format!("💡 Hint: {}", h)).unwrap_or_default();
        let dragon_widget = Paragraph::new(format!("{}\n{}", dragon_art, hint))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("🐉 DragonGuard - Your Digital Hoard")
                    .style(Style::default().fg(Color::Red)),
            )
            .style(Style::default().fg(Color::Yellow))
            .wrap(Wrap { trim: true });
        f.render_widget(dragon_widget, area);
    }

    pub fn render_vault_view(&mut self, f: &mut Frame, area: Rect) {
        let entries = self.vault.list_entries();
        if entries.is_empty() {
            let empty_msg = Paragraph::new(
                "🐉 Your vault is empty!\n\nPress 'a' to add a secret.\nPress 'g' to forge dragon eggs.\nPress 'h' for help.",
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("📦 Vault Contents"),
            )
            .style(Style::default().fg(Color::Gray))
            .wrap(Wrap { trim: true });
            f.render_widget(empty_msg, area);
            return;
        }
        let items: Vec<ListItem> = entries
            .iter()
            .map(|entry| {
                let prefix = if entry.tags.contains(&"crypto".to_string()) { "🥚" } else { "🔐" };
                let content = vec![
                    Line::from(vec![
                        Span::raw(format!("{} ", prefix)),
                        Span::styled(
                            &entry.name,
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" "),
                        Span::raw(entry.strength_emoji()),
                    ]),
                    Line::from(vec![
                        Span::raw("   📝 "),
                        Span::styled(
                            entry.notes.as_deref().unwrap_or("(no notes)"),
                            Style::default().fg(Color::Cyan),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("   🕐 "),
                        Span::styled(
                            entry.created_at.format("%Y-%m-%d %H:%M").to_string(),
                            Style::default().fg(Color::Gray),
                        ),
                    ]),
                ];
                ListItem::new(content)
            })
            .collect();
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("📦 Vault Contents ({} entries)", entries.len())),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("🐉 ");
        f.render_stateful_widget(list, area, &mut self.list_state);
    }

    pub fn render_add_entry(&self, f: &mut Frame, area: Rect) {
        let (name, username, password, notes) = &self.add_entry_data;
        let current_field = match self.input_field {
            InputField::Name => format!("Name: {}\nUsername: {}\nPassword: {}\nNotes: {}", self.input_buffer, username.as_deref().unwrap_or(""), password, notes.as_deref().unwrap_or("")),
            InputField::Username => format!("Name: {}\nUsername: {}\nPassword: {}\nNotes: {}", name, self.input_buffer, password, notes.as_deref().unwrap_or("")),
            InputField::Password => format!("Name: {}\nUsername: {}\nPassword: {}\nNotes: {}", name, username.as_deref().unwrap_or(""), self.input_buffer, notes.as_deref().unwrap_or("")),
            InputField::Notes => format!("Name: {}\nUsername: {}\nPassword: {}\nNotes: {}", name, username.as_deref().unwrap_or(""), password, self.input_buffer),
            _ => String::new(),
        };
        let add_form = Paragraph::new(format!(
            "🐉 Add New Entry\n\n[Enter details and press Enter to move]\n[Esc to cancel]\n\n{}",
            current_field
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    "➕ Add Entry - {}",
                    match self.input_field {
                        InputField::Name => "Enter name",
                        InputField::Username => "Enter username (optional)",
                        InputField::Password => "Enter password (empty for random)",
                        InputField::Notes => "Enter notes (optional)",
                        _ => "",
                    }
                ))
                .style(Style::default().fg(Color::Green)),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });
        f.render_widget(Clear, area);
        f.render_widget(add_form, area);
    }

    pub fn render_generate_phrase(&self, f: &mut Frame, area: Rect) {
        let (name, word_count) = &self.phrase_data;
        let current_field = match self.input_field {
            InputField::PhraseName => format!(
                "Name: {}\nWord Count (12, 15, 18, 21, 24): {}",
                self.input_buffer, word_count
            ),
            InputField::PhraseWordCount => format!(
                "Name: {}\nWord Count (12, 15, 18, 21, 24): {}",
                name, self.input_buffer
            ),
            _ => String::new(),
        };
        let phrase_form = Paragraph::new(format!(
            "🐉 Forge Dragon Eggs (BIP-39 Phrase)\n\n[Enter details and press Enter to generate]\n[Esc to cancel]\n\n{}",
            current_field
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    "🥚 Generate Secret Phrase - {}",
                    match self.input_field {
                        InputField::PhraseName => "Enter name",
                        InputField::PhraseWordCount => "Enter word count",
                        _ => "",
                    }
                )),
        )
        .style(Style::default().fg(Color::Green))
        .wrap(Wrap { trim: true });
        f.render_widget(Clear, area);
        f.render_widget(phrase_form, area);
    }

    pub fn render_view_entry(&self, f: &mut Frame, area: Rect) {
        if let Some(selected) = self.selected_entry {
            if let Some(entry) = self.vault.list_entries().get(selected) {
                let prefix = if entry.tags.contains(&"crypto".to_string()) { "🥚" } else { "🔐" };
                let content = format!(
                    "{} Name: {}\n\n📝 Notes: {}\n\n{} Password: {}\n   {}\n\n🕐 Created: {}\n\nPress 'c' to copy password\nPress 'q' or Esc to go back",
                    prefix,
                    entry.name,
                    entry.notes.as_deref().unwrap_or("(none)"),
                    prefix,
                    "*".repeat(entry.password.len()),
                    entry.strength_label(),
                    entry.created_at.format("%Y-%m-%d %H:%M")
                );
                let details = Paragraph::new(content)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("🔍 Entry Details"),
                    )
                    .style(Style::default().fg(Color::White))
                    .wrap(Wrap { trim: true });
                f.render_widget(Clear, area);
                f.render_widget(details, area);
            }
        }
    }

    pub fn render_check_breach(&self, f: &mut Frame, area: Rect) {
        let content = if let Some(selected) = self.list_state.selected() {
            if let Some(entry) = self.vault.list_entries().get(selected) {
                format!(
                    "🐉 Checking Breach Status for '{}'\n\nPress Enter to check with HIBP\nPress 'q' or Esc to go back",
                    entry.name
                )
            } else {
                "❌ No entry selected!\n\nPress 'q' or Esc to go back".to_string()
            }
        } else {
            "❌ No entry selected!\n\nPress 'q' or Esc to go back".to_string()
        };
        let breach_check = Paragraph::new(content)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("🔍 Check Breach Status"),
            )
            .style(Style::default().fg(Color::Yellow))
            .wrap(Wrap { trim: true });
        f.render_widget(Clear, area);
        f.render_widget(breach_check, area);
    }

    pub fn render_help(&self, f: &mut Frame, area: Rect) {
        let help_text = "🐉 DragonGuard Help\n\n\
            NAVIGATION:\n\
            ↑/↓     - Navigate entries\n\
            Enter   - View entry details\n\
            a       - Add new entry\n\
            g       - Generate BIP-39 phrase\n\
            b       - Check entry for breaches\n\
            Del     - Delete selected entry\n\
            h/F1    - Show this help\n\
            q       - Quit\n\n\
            ENTRY VIEW:\n\
            c       - Copy password to clipboard\n\
            q/Esc   - Return to vault view\n\n\
            SECURITY:\n\
            🔴 Weak  🟡 Fair  🟢 Strong/Excellent passwords\n\
            🥚 Crypto phrases (BIP-39 compatible)\n\
            AES-256-GCM encryption\n\
            Argon2 key derivation\n\
            HMAC-SHA256 integrity\n\
            Zero-knowledge design\n\n\
            Press any key to return...";
        let help = Paragraph::new(help_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("❓ Help & Controls"),
            )
            .style(Style::default().fg(Color::Cyan))
            .wrap(Wrap { trim: true });
        f.render_widget(Clear, area);
        f.render_widget(help, area);
    }

    pub fn render_status_bar(&self, f: &mut Frame, area: Rect) {
        let status_text = match self.state {
            AppState::VaultView => "🐉 q:quit | a:add | g:generate | b:breach check | h:help | ↑↓:navigate | Enter:view | Del:delete",
            AppState::AddEntry => "➕ Esc:cancel | Enter:next field/save",
            AppState::GeneratePhrase => "🥚 Esc:cancel | Enter:next field/generate",
            AppState::ViewEntry => "🔍 c:copy password | q/Esc:back",
            AppState::CheckBreach => "🔍 Enter:check breach | q/Esc:back",
            AppState::Help => "❓ Press any key to return",
            AppState::Error(_) => "🐉 Press Enter, q, or Esc to continue",
            AppState::Welcome => "🏠 Press Enter to start or 'h' for help",
        };
        let status = Paragraph::new(status_text)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::Yellow));
        f.render_widget(status, area);
    }

    pub fn render_error(&self, f: &mut Frame, area: Rect, message: &str) {
        let error = Paragraph::new(message)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("🐉 DragonGuard Status"),
            )
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true });
        f.render_widget(Clear, area);
        f.render_widget(error, area);
    }
}

pub async fn animate_sniffing() -> Result<()> {
    let frames = vec![
        "🐉 Sniffing... *snort*",
        "🐉 Sniffing... *puff*",
        "🐉 Sniffing... *hiss*",
        "🐉 Sniffing... *roar*",
    ];
    for frame in frames.iter().cycle().take(8) {
        print!("\r{}", frame);
        io::stdout().flush()?;
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }
    println!("\r{}", " ".repeat(20));
    Ok(())
}

pub fn display_dragon_intro() {
    println!(r#"
    🐉🔥 DRAGONGUARD 🔥🐉
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
     and guard your secrets with steel and flame."
    Forging your impenetrable vault..."#
    );
}

pub fn get_dragon_frame(frame: usize) -> &'static str {
    match frame % 4 {
        0 => r#"
🐉 DRAGONGUARD 🐉

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
            (   o.o /   Your secrets are safe
             `-._.-'    in my lair!
"#,
        1 => r#"
🐉 DRAGONGUARD 🐉

               /           / 
              /' .,,,,  ./       
             /';'     ,/      
            / /   ,,//,`'`    
           ( ,, '_,  ,,,' ``  
           |    /-o  ,,, ;" `  
          /    .   ,''/' `,`` 
         /   .     ./, `,, ` ; 
      ,./  .   ,-,',` ,,/''\,' 
     |   /; ./,,'`,,'' |   |   
     |     /   ','    /    |   
      \___/'   '     |     |   
        `,,'  |      /     `\   
             /      |        
            (   -.o /   Sniffing for intruders...
             `-._.-'    
"#,
        2 => r#"
🐉 DRAGONGUARD 🐉

               /           / 
              /' .,,,,  ./       
             /';'     ,/      
            / /   ,,//,`'`    
           ( ,, '_,  ,,,' ``  
           |    /o-  ,,, ;" `  
          /    .   ,''/' `,`` 
         /   .     ./, `,, ` ; 
      ,./  .   ,-,',` ,,/''\,' 
     |   /; ./,,'`,,'' |   |   
     |     /   ','    /    |   
      \___/'   '     |     |   
        `,,'  |      /     `\   
             /      |        
            (   o.- /   Guarding your hoard...
             `-._.-'    
"#,
        _ => r#"
🐉 DRAGONGUARD 🐉

               /           / 
              /' .,,,,  ./       
             /';'     ,/      
            / /   ,,//,`'`    
           ( ,, '_,  ,,,' ``  
           |    /o-  ,,, ;" `  
          /    .   ,''/' `,`` 
         /   .     ./, `,, ` ; 
      ,./  .   ,-,',` ,,/''\,' 
     |   /; ./,,'`,,'' |   |   
     |     /   ','    /    |   
      \___/'   '     |     |   
        `,,'  |      /     `\   
             /      |        
            (   -.o /   Roaring with strength!
             `-._.-'    
"#,
    }
}