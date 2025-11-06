# 🤝 Contributing to KeyRex

Thank you for your interest in contributing to **KeyRex**!

---

## 🧱 Getting Started

### 1. Fork and Clone

Start by forking the repository and cloning it locally:

```bash
git clone https://github.com/spinualexandru/keyrex.git
cd keyrex
```

### 2. Create a Feature Branch

Create a new branch for your feature or fix:

```bash
git checkout -b feature/my-improvement
```

### 3. Build and Test

Ensure everything builds and passes before submitting:

```bash
cargo build
cargo test
```

### 4. Commit and Push

Use clear and descriptive commit messages:

```bash
git commit -m "Add: clear description of your change"
git push origin feature/my-improvement
```

### 5. Submit a Pull Request

Open a Pull Request (PR) from your fork to the main branch.
Provide a concise description of:

* What the change does
* Why it’s needed
* Any potential impact on existing functionality

---

## 🧩 Code Standards

KeyRex follows clean, auditable Rust practices.
Please ensure your code adheres to these principles:

* Use `cargo fmt` and `cargo clippy` before committing:

  ```bash
  cargo fmt
  cargo clippy -- -D warnings
  ```
* Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
* Write **small, modular functions** and **clear documentation comments** (`///`).
* Avoid unnecessary abstractions — prioritize security, simplicity, and readability.

---

## 🧪 Testing Guidelines

All code must be tested before merging.
Run the full suite using:

```bash
cargo test -- --nocapture
```

When introducing new functionality:

* Add **unit tests** for both success and failure cases.
* Add **negative tests** for invalid passwords, corrupted data, or wrong formats (especially for crypto code).
* If possible, include **property-based tests** using `quickcheck` or similar.

---

## 🛡️ Security Contributions

If you discover a vulnerability, **please do reach out**.

---

## 💡 Feature Suggestions

We welcome ideas for improvements, integrations, or UX enhancements.

You can:

* Open a **Discussion** at [GitHub Discussions](https://github.com/spinualexandru/keyrex/discussions)
* Or file an **Issue**

Before suggesting a new feature, check existing issues to avoid duplicates.

---

## 🧾 Licensing

By contributing to KeyRex, you agree that your contributions are licensed under the same terms as the project:

> **Apache License 2.0**
> See the full license in [`LICENSE`](./LICENSE).

---

## 🧠 Development Tips

* **Code organization**:

  * `src/crypto.rs` handles AES encryption and key derivation
  * `src/commands.rs` manages vault commands
  * `src/vault.rs` handles storage and serialization
  * `src/cli.rs` defines the command-line interface
* **Testing crypto**: never use hardcoded salts or keys; always rely on generated randomness.
* **Documentation**: Update `README.md` or `ENCRYPTION.md` if your change affects the CLI or encryption logic.

---

## 🧑‍💻 Code of Conduct

Please be respectful and constructive.
All contributors are expected to follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

---

## 💬 Credits

KeyRex is maintained by **[Alexandru-Mihai Spinu](https://github.com/spinualexandru)**

If you make a meaningful contribution, you’ll be added to the project’s **Contributors** list.
