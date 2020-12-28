use crossterm::{execute, terminal, event::{self, Event::*, KeyCode}, style::Print, cursor};
use crate::error::LuksError;
use std::io::stdout;

/// Reads a password from stdin, replacing every typed character with a '*' and returning on Enter.
///
/// Supports deleting already entered characters via backspace. Does not prompt for input.
pub fn read() -> Result<String, LuksError> {
	terminal::enable_raw_mode()?;
	let mut password = String::with_capacity(10);
	loop {
		match event::read()? {
			Key(e) => {
				match e.code {
					KeyCode::Char(c) => { password.push(c); print_char('*')? },
					KeyCode::Enter => { print_char('\n')?; break },
					KeyCode::Backspace => { password.remove(password.len() - 1); delete_char()? },
					_ => {}
				}
			},
			_ => {}
		}
	}

	terminal::disable_raw_mode()?;

	Ok(password)
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
