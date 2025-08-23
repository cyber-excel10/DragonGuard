pub mod models;
pub mod security;
pub mod tui;
pub mod utils;
pub mod vault;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_all_functions() -> Result<()> {
        //  this calls  security.rs functions
        let _ = security::generate_phrase(12).await?;

        // Call utils.rs functions
        let _ = utils::prompt_input("Test prompt: ").await?;
        let _ = utils::validate_password_strength("Test123!").await?;
        let _ = utils::generate_secure_password(12).await?;
        let _ = utils::validate_entry_name("test_entry")?;
        let _ = utils::check_common_patterns("password123");
        let _ = utils::has_sequential_chars("abc123");
        let _ = utils::has_repeated_chars("aaa123");
        let _ = utils::format_file_size(1024);

        // this calls tui.rs functions
        tui::display_dragon_intro();
        let _ = tui::get_dragon_frame(0);

        // this also calls DragonTui methods in tui.rs file
        let mut vault = VaultManager::new(PathBuf::from("vault.dat"), master_password);
        let mut tui = DragonTui::new(&mut vault, master_password);
        tui.run().await?;

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

        Ok(())
    }
}