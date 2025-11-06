//! Command handling and routing
//!
//! This module contains all command handlers organized by functionality:
//! - `crud`: Create, Read, Update, Delete operations
//! - `query`: Search and information display
//! - `security`: Encryption and decryption
//! - `meta`: Vault management operations

mod crud;
mod meta;
mod query;
mod security;

use crate::cli::Command;
use crate::completions;
use crate::vault::Vault;

/// Route CLI commands to their respective handlers
pub fn handle_command(command: Command, vault: &mut Vault, is_encrypted: bool) {
    match command {
        Command::Add { key, value } => crud::handle_add(vault, key, value, is_encrypted),
        Command::Get { key, copy } => crud::handle_get(vault, key, copy, is_encrypted),
        Command::Update { key, value } => crud::handle_update(vault, key, value, is_encrypted),
        Command::Remove { key, yes } => crud::handle_remove(vault, key, yes, is_encrypted),
        Command::List { values, sort } => query::handle_list(vault, values, sort),
        Command::Search { pattern, values } => query::handle_search(vault, pattern, values),
        Command::Info => query::handle_info(vault, is_encrypted),
        Command::Clear { yes } => meta::handle_clear(vault, yes, is_encrypted),
        Command::Keys => query::handle_keys(vault),
        Command::Completions { shell } => completions::handle_completions(shell),
        Command::Encrypt => security::handle_encrypt(vault, is_encrypted),
        Command::Decrypt => security::handle_decrypt(vault, is_encrypted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestVault;

    // Helper function to set up a test vault with entries
    fn setup_test_vault_with_entries() -> (TestVault, Vault) {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();

        Vault::set_vault_path(vault_path).unwrap();

        let mut vault = Vault::new();
        vault
            .add_entry("test_key1".to_string(), "test_value1".to_string())
            .unwrap();
        vault
            .add_entry("test_key2".to_string(), "test_value2".to_string())
            .unwrap();
        vault
            .add_entry("password_db".to_string(), "secret_db_pwd".to_string())
            .unwrap();

        (test_vault, vault)
    }

    // Tests for query operations
    #[test]
    fn test_list_operation_empty_vault() {
        let test_vault = TestVault::new();
        Vault::set_vault_path(test_vault.path()).unwrap();
        let vault = Vault::new();

        // Should handle empty vault gracefully
        assert_eq!(vault.entry_count(), 0);
        assert_eq!(vault.list_entries().len(), 0);
    }

    #[test]
    fn test_list_operation_with_entries() {
        let (_test_vault, vault) = setup_test_vault_with_entries();

        let entries = vault.list_entries();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_list_operation_sorting() {
        let (_test_vault, vault) = setup_test_vault_with_entries();

        let mut entries = vault.list_entries();
        let original_order = entries.iter().map(|e| &e.key).collect::<Vec<_>>();

        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let sorted_order = entries.iter().map(|e| &e.key).collect::<Vec<_>>();

        // Check that sorted order is indeed sorted
        assert_eq!(sorted_order, vec!["password_db", "test_key1", "test_key2"]);
        assert_ne!(original_order, sorted_order);
    }

    #[test]
    fn test_search_operation_by_key() {
        let (_test_vault, vault) = setup_test_vault_with_entries();

        let results = vault.search_entries("test_key");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_operation_by_value() {
        let (_test_vault, vault) = setup_test_vault_with_entries();

        let results = vault.search_entries("secret");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "password_db");
    }

    #[test]
    fn test_search_operation_no_matches() {
        let (_test_vault, vault) = setup_test_vault_with_entries();

        let results = vault.search_entries("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_operation_case_insensitive() {
        let (_test_vault, vault) = setup_test_vault_with_entries();

        let results_lower = vault.search_entries("password");
        let results_upper = vault.search_entries("PASSWORD");
        let results_mixed = vault.search_entries("PaSsWoRd");

        assert_eq!(results_lower.len(), results_upper.len());
        assert_eq!(results_lower.len(), results_mixed.len());
        assert_eq!(results_lower.len(), 1);
    }

    #[test]
    fn test_info_operation_metadata() {
        let (_test_vault, vault) = setup_test_vault_with_entries();

        // Test that vault has correct metadata
        assert_eq!(vault.entry_count(), 3);
        assert!(vault.created_at <= chrono::Utc::now());
        assert!(vault.last_updated_at <= chrono::Utc::now());
    }

    // Tests for CRUD operations
    #[test]
    fn test_add_entry_basic() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let initial_count = vault.entry_count();
        vault
            .add_entry("new_key".to_string(), "new_value".to_string())
            .unwrap();

        assert_eq!(vault.entry_count(), initial_count + 1);
        assert_eq!(
            vault.get_entry("new_key").unwrap().value,
            "new_value".to_string()
        );
    }

    #[test]
    fn test_add_entry_overwrites_existing() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Add with existing key - should overwrite
        vault
            .add_entry("test_key1".to_string(), "new_value".to_string())
            .unwrap();

        assert_eq!(vault.entry_count(), 3); // Count should not increase
        assert_eq!(
            vault.get_entry("test_key1").unwrap().value,
            "new_value".to_string()
        );
    }

    #[test]
    fn test_add_entry_validation() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Empty key should fail
        assert!(vault
            .add_entry("".to_string(), "value".to_string())
            .is_err());

        // Empty value should fail
        assert!(vault.add_entry("key".to_string(), "".to_string()).is_err());

        // Very long key should fail
        assert!(vault
            .add_entry("k".repeat(257), "value".to_string())
            .is_err());
    }

    #[test]
    fn test_get_entry_success() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let entry = vault.get_entry("test_key1");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().value, "test_value1".to_string());
    }

    #[test]
    fn test_get_entry_not_found() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let entry = vault.get_entry("nonexistent_key");
        assert!(entry.is_none());
    }

    #[test]
    fn test_get_entry_updates_access_time() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let old_access_time = vault.last_accessed_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        vault.get_entry("test_key1");

        assert!(vault.last_accessed_at > old_access_time);
    }

    #[test]
    fn test_update_entry_success() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let result = vault.update_entry("test_key1", "updated_value".to_string());
        assert!(result.is_ok());
        assert_eq!(
            vault.get_entry("test_key1").unwrap().value,
            "updated_value".to_string()
        );
    }

    #[test]
    fn test_update_entry_not_found() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let result = vault.update_entry("nonexistent_key", "value".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_update_entry_validation() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Empty value should fail
        let result = vault.update_entry("test_key1", "".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_update_entry_updates_timestamp() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let old_updated = vault.last_updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        vault
            .update_entry("test_key1", "new_value".to_string())
            .unwrap();

        assert!(vault.last_updated_at > old_updated);
    }

    #[test]
    fn test_remove_entry_success() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let initial_count = vault.entry_count();
        let removed = vault.remove_entry("test_key1");

        assert!(removed.is_some());
        assert_eq!(vault.entry_count(), initial_count - 1);
        assert!(vault.get_entry("test_key1").is_none());
    }

    #[test]
    fn test_remove_entry_not_found() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let removed = vault.remove_entry("nonexistent_key");
        assert!(removed.is_none());
    }

    #[test]
    fn test_remove_entry_updates_timestamp() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        let old_updated = vault.last_updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        vault.remove_entry("test_key1");

        assert!(vault.last_updated_at > old_updated);
    }

    // Integration-like tests for combined operations
    #[test]
    fn test_add_search_remove_workflow() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Add an entry
        vault
            .add_entry("api_token".to_string(), "secret123".to_string())
            .unwrap();

        // Search for it
        let results = vault.search_entries("api");
        assert_eq!(results.len(), 1);

        // Remove it
        vault.remove_entry("api_token");

        // Verify it's gone
        let results = vault.search_entries("api");
        assert!(results.is_empty());
    }

    #[test]
    fn test_add_update_get_workflow() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Add entry
        vault
            .add_entry("username".to_string(), "john".to_string())
            .unwrap();

        // Get it
        assert_eq!(vault.get_entry("username").unwrap().value, "john");

        // Update it
        vault.update_entry("username", "jane".to_string()).unwrap();

        // Get updated value
        assert_eq!(vault.get_entry("username").unwrap().value, "jane");
    }

    #[test]
    fn test_complex_search_and_list() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Add more entries with different prefixes
        vault
            .add_entry("email_gmail".to_string(), "user@gmail.com".to_string())
            .unwrap();
        vault
            .add_entry("email_work".to_string(), "user@company.com".to_string())
            .unwrap();
        vault
            .add_entry("phone".to_string(), "555-1234".to_string())
            .unwrap();

        assert_eq!(vault.entry_count(), 6);

        // Search for email entries
        let email_results = vault.search_entries("email");
        assert_eq!(email_results.len(), 2);

        // Search for all contact info
        let contact_results = vault.search_entries("@");
        assert_eq!(contact_results.len(), 2);

        // List all
        let all = vault.list_entries();
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn test_persistence_workflow() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();

        {
            Vault::set_vault_path(vault_path.clone()).unwrap();
            let mut vault = Vault::new();

            vault
                .add_entry("persist_key".to_string(), "persist_value".to_string())
                .unwrap();
            vault.save().unwrap();
        }

        {
            Vault::set_vault_path(vault_path.clone()).unwrap();
            let mut vault = Vault::load().unwrap();

            // Verify entry persisted
            assert_eq!(
                vault.get_entry("persist_key").unwrap().value,
                "persist_value".to_string()
            );

            // Make additional changes
            vault
                .update_entry("persist_key", "updated_value".to_string())
                .unwrap();
            vault.save().unwrap();
        }

        {
            Vault::set_vault_path(vault_path).unwrap();
            let mut vault = Vault::load().unwrap();

            // Verify all changes persisted
            assert_eq!(
                vault.get_entry("persist_key").unwrap().value,
                "updated_value".to_string()
            );
        }
    }

    #[test]
    fn test_special_characters_in_operations() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Add entries with special characters
        vault
            .add_entry("api_key!@#$".to_string(), "value!@#$%^&*()".to_string())
            .unwrap();
        vault
            .add_entry(
                "path/with\\backslash".to_string(),
                "C:\\Users\\name".to_string(),
            )
            .unwrap();
        vault
            .add_entry("emoji_🔑".to_string(), "password_🔒".to_string())
            .unwrap();

        // Verify they can be retrieved
        assert_eq!(
            vault.get_entry("api_key!@#$").unwrap().value,
            "value!@#$%^&*()"
        );
        assert_eq!(
            vault.get_entry("path/with\\backslash").unwrap().value,
            "C:\\Users\\name"
        );
        assert_eq!(vault.get_entry("emoji_🔑").unwrap().value, "password_🔒");

        // Verify search works
        let results = vault.search_entries("emoji");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_large_value_handling() {
        let (_test_vault, mut vault) = setup_test_vault_with_entries();

        // Create a large value (close to 64KB limit)
        let large_value = "x".repeat(60000);

        vault
            .add_entry("large_entry".to_string(), large_value.clone())
            .unwrap();

        assert_eq!(vault.get_entry("large_entry").unwrap().value, large_value);
    }
}
