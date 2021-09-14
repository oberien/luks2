use crate::error::LuksError;
use crossterm::{
    cursor,
    event::{self, Event::*, KeyCode},
    execute,
    style::Print,
    terminal,
};
use secrecy::{Secret, SecretString};
use std::io::stdout;

/// Reads a password from stdin, replacing every typed character with a '*' and returning on Enter.
///
/// Supports deleting already entered characters via backspace. Does not prompt for input.
pub fn read() -> Result<SecretString, LuksError> {
    terminal::enable_raw_mode()?;
    let mut password = String::with_capacity(10);
    loop {
        match event::read()? {
            Key(e) => match e.code {
                KeyCode::Char(c) => {
                    password.push(c);
                    print_char('*')?
                }
                KeyCode::Enter => break,
                KeyCode::Backspace => {
                    if password.len() > 0 {
                        password.remove(password.len() - 1);
                    }
                    delete_char()?
                }
                _ => {}
            },
            _ => {}
        }
    }

    terminal::disable_raw_mode()?;
    print_char('\n')?;

    Ok(Secret::new(password))
}

fn print_char(c: char) -> Result<(), LuksError> {
    execute!(stdout(), Print(c))?;
    Ok(())
}

fn delete_char() -> Result<(), LuksError> {
    execute!(stdout(), cursor::MoveLeft(1))?;
    print_char(' ')?;
    execute!(stdout(), cursor::MoveLeft(1))?;
    Ok(())
}
