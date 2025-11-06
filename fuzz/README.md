# Fuzzing KeyRex

This directory contains fuzz targets for KeyRex using `cargo-fuzz` (libFuzzer).

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

Note: Fuzzing requires a nightly Rust toolchain.

## Running Fuzz Tests

### Fuzz Encrypt/Decrypt
Tests the encryption and decryption functions with arbitrary inputs:
```bash
cargo +nightly fuzz run fuzz_encrypt_decrypt
```

### Fuzz Vault Operations
Tests vault CRUD operations with arbitrary key-value pairs:
```bash
cargo +nightly fuzz run fuzz_vault_operations
```

### Fuzz Password Validation
Tests password validation with arbitrary strings:
```bash
cargo +nightly fuzz run fuzz_password_validation
```

### Fuzz JSON Parsing
Tests vault deserialization with arbitrary JSON-like input:
```bash
cargo +nightly fuzz run fuzz_json_parsing
```

## Running with Time Limit

Run fuzzing for a specific duration (e.g., 60 seconds):
```bash
cargo +nightly fuzz run fuzz_encrypt_decrypt -- -max_total_time=60
```

## Running with Corpus

List available targets:
```bash
cargo +nightly fuzz list
```

Build all fuzz targets:
```bash
cargo +nightly fuzz build
```

## Coverage

Generate coverage report:
```bash
cargo +nightly fuzz coverage fuzz_encrypt_decrypt
```

## Crash Investigation

If a crash is found, it will be saved to:
```
fuzz/artifacts/fuzz_<target_name>/
```

Reproduce a crash:
```bash
cargo +nightly fuzz run fuzz_encrypt_decrypt fuzz/artifacts/fuzz_encrypt_decrypt/crash-<hash>
```

## Continuous Fuzzing

For continuous fuzzing in CI or production:
```bash
# Run for 1 hour
cargo +nightly fuzz run fuzz_encrypt_decrypt -- -max_total_time=3600

# Run with multiple jobs (parallel fuzzing)
cargo +nightly fuzz run fuzz_encrypt_decrypt -- -jobs=4
```

## Tips

1. **Start Simple**: Begin with shorter time limits (e.g., 60 seconds) to verify targets work
2. **Use Multiple Cores**: Add `-jobs=N` for parallel fuzzing
3. **Monitor Memory**: Fuzzing can be memory-intensive, use `-rss_limit_mb=2048`
4. **Save Corpus**: The corpus (interesting inputs) is saved automatically for future runs

## What Each Target Tests

- **fuzz_encrypt_decrypt**: Encryption/decryption roundtrip, wrong password handling
- **fuzz_vault_operations**: CRUD operations, validation, consistency
- **fuzz_password_validation**: Password strength checking, edge cases
- **fuzz_json_parsing**: Deserialization, malformed JSON handling

## Expected Behavior

These fuzz targets should:
- Never panic (except for explicit assertions when invariants are violated)
- Handle all invalid input gracefully
- Maintain consistency (e.g., encrypt then decrypt should return original)

## Integration with CI

To run fuzzing in CI with a time limit:
```yaml
- name: Fuzz testing
  run: |
    cargo install cargo-fuzz
    cargo +nightly fuzz run fuzz_encrypt_decrypt -- -max_total_time=60
    cargo +nightly fuzz run fuzz_vault_operations -- -max_total_time=60
    cargo +nightly fuzz run fuzz_password_validation -- -max_total_time=60
    cargo +nightly fuzz run fuzz_json_parsing -- -max_total_time=60
```

## Troubleshooting

### "no such command: fuzz"
Install cargo-fuzz: `cargo install cargo-fuzz`

### "requires nightly"
Use nightly toolchain: `cargo +nightly fuzz run <target>`

### "linker error"
Install required system libraries (varies by OS)

### Fuzzing is slow
- Reduce `-max_total_time` for quick checks
- Use `-jobs=1` to reduce CPU usage
- Check that release mode is being used (cargo-fuzz does this automatically)

## Further Reading

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
