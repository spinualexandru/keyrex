//! Clipboard integration.
//!
//! Wayland requires a clipboard owner to remain available after the CLI exits.
//! `wl-copy` handles that by forking into the background, so prefer it when
//! running in a Wayland session and fall back to arboard elsewhere.

use arboard::Clipboard;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClipboardError {
    #[error("wl-copy failed: {0}")]
    WlCopyIo(#[source] io::Error),

    #[error("wl-copy exited with status {0}")]
    WlCopyStatus(String),

    #[error("clipboard not available: {0}")]
    Arboard(#[from] arboard::Error),
}

pub fn copy_text(text: &str) -> Result<(), ClipboardError> {
    if is_wayland_session() {
        match copy_with_wl_copy(text) {
            Ok(()) => return Ok(()),
            Err(ClipboardError::WlCopyIo(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(text.to_string())?;
    Ok(())
}

fn is_wayland_session() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some()
}

fn copy_with_wl_copy(text: &str) -> Result<(), ClipboardError> {
    let mut child = Command::new("wl-copy")
        .arg("--type")
        .arg("text/plain")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(ClipboardError::WlCopyIo)?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(text.as_bytes())
            .map_err(ClipboardError::WlCopyIo)?;
    }

    let status = child.wait().map_err(ClipboardError::WlCopyIo)?;
    if status.success() {
        Ok(())
    } else {
        Err(ClipboardError::WlCopyStatus(status.to_string()))
    }
}
