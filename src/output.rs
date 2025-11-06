//! Terminal output utilities and user interaction
//!
//! This module provides consistent, colored terminal output and user interaction
//! functions like confirmation prompts.

use colored::Colorize;
use std::io::{self, Write};

/// Print a success message in green
#[allow(dead_code)]
pub fn success(message: &str) {
    println!("{}", message.green().bold());
}

/// Print an error message in red to stderr
#[allow(dead_code)]
pub fn error(message: &str) {
    eprintln!("{}", message.red().bold());
}

/// Print a warning message in yellow to stderr
#[allow(dead_code)]
pub fn warning(message: &str) {
    eprintln!("{}", message.yellow().bold());
}

/// Print an info message in cyan to stderr
#[allow(dead_code)]
pub fn info(message: &str) {
    eprintln!("{}", message.cyan().bold());
}

/// Prompt user for yes/no confirmation
///
/// Displays the prompt in yellow and waits for user input.
/// Returns true if user enters 'y' or 'yes' (case-insensitive).
pub fn confirm(prompt: &str) -> io::Result<bool> {
    print!("{} ", prompt.yellow().bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}
