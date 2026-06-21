# Contributing to HASA

Thank you for your interest in contributing! Since HASA is a custom cryptographic scheme, **security reviews are especially valuable.**

---

## 🐛 Reporting Bugs

Open an [Issue](https://github.com/Yun131518/HASA/issues) and include:
- Java version (`java -version`)
- Steps to reproduce
- Expected vs actual behavior

## 🔐 Reporting Security Vulnerabilities

**Please do not open a public issue for security vulnerabilities.**  
Instead, describe the issue in a private manner via GitHub's [Security Advisories](https://github.com/Yun131518/HASA/security/advisories) or contact the maintainer directly.

Areas of particular interest:
- Weaknesses in the nonce generation scheme
- Signature malleability
- Side-channel attack vectors
- Deviations from standard Schnorr security properties

---

## 🛠️ Submitting Pull Requests

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-change`
3. Make your changes in `src/`
4. Build and test:
    ```bash
    javac -encoding UTF-8 -cp lib/bcprov-jdk18on-1.84.jar \
      -d bin src/main/java/com/hasa/crypto/*.java
    java -jar HASA_EXE.jar
    ```
5. Commit with a clear message
6. Open a Pull Request against `main`

---

## 📐 Code Style

- Standard Java conventions
- No external dependencies beyond Bouncy Castle
- Keep `HASA.java` focused on the core cryptographic primitives
- CLI logic stays in `Main.java`

---

## 💡 Ideas Welcome

- Unit tests
- Maven / Gradle build support
- Additional key export formats (DER, raw hex)
- Multi-signature schemes
- Port to other languages
