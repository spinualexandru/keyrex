//! KeyRex library
//!
//! This library provides the core functionality for the KeyRex vault system.
//! It is primarily used by the keyrex binary, but can also be used as a library
//! for testing and integration purposes.

pub mod cli;
pub mod commands;
pub mod completions;
pub mod config;
pub mod crypto;
pub mod logging;
pub mod output;
pub mod security;
pub mod session;
pub mod vault;

// Test utilities should only be available in test mode
#[cfg(test)]
pub mod test_utils;
