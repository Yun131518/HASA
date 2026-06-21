<div align="center">

# ⚡ HASA

**A lightweight secp256k1 digital signature library & CLI tool for Java**

![Java](https://img.shields.io/badge/Java-17%2B-orange?style=for-the-badge&logo=openjdk)
![Curve](https://img.shields.io/badge/Curve-secp256k1-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![BouncyCastle](https://img.shields.io/badge/BouncyCastle-1.84-purple?style=for-the-badge)

[한국어](README_KO.md) | **English**

</div>

---

## 📖 What is HASA?

**HASA** is a digital signature library built on the **secp256k1** elliptic curve — the same curve powering Bitcoin and Ethereum — backed by [Bouncy Castle](https://www.bouncycastle.org/).

It implements a custom **Schnorr-style signature scheme** with:
- Tagged hash functions for domain separation (`NONCE-V1`, `CHALLENGE-V1`)
- Deterministic nonce generation (no random k leakage risk)
- Compact PEM encoding for keys and signatures

> ⚠️ **Note:** HASA is a custom cryptographic scheme for educational and research purposes. It has **not** been audited. Do not use it in production systems where security is critical. Contributions and security reviews are very welcome!

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔑 Key Generation | secp256k1 key pair generation |
| ✍️ Sign | Schnorr-style deterministic signing |
| ✅ Verify | Signature verification |
| 📄 File Sign | Sign any file by its raw bytes |
| 🔒 PEM Codec | Human-readable PEM format for keys & signatures |
| 💻 CLI Tool | Interactive terminal interface |

---

## 📁 Project Structure

```
HASA/
├── src/main/java/com/hasa/crypto/
│   ├── HASA.java           # Core: key gen, sign, verify, hash
│   ├── HASAPemCodec.java   # PEM encode/decode
│   └── Main.java           # Interactive CLI
├── lib/
│   └── bcprov-jdk18on-1.84.jar   # Bouncy Castle
├── readme/
│   ├── README_EN.md        # This file
│   └── README_KO.md        # Korean version
├── HASA_17.jar             # Library JAR (Java 17, fat)
├── HASA_EXE.jar            # Executable CLI JAR (Java 17, fat)
├── CONTRIBUTING.md
└── LICENSE
```

---

## 🚀 Getting Started

### Requirements
- Java 17 or higher

### Download

Grab the latest JARs from the repository root:

| File | Purpose |
|---|---|
| `HASA_17.jar` | Use as a library dependency |
| `HASA_EXE.jar` | Run as a standalone CLI tool |

---

## 💻 CLI Usage

```bash
java -jar HASA_EXE.jar
```

```
╔══════════════════════════════════════╗
║   HASA CLI - secp256k1 서명 도구     ║
╚══════════════════════════════════════╝

─────────────────────────────────────
  1. 키페어 생성   (Generate Key Pair)
  2. 메시지 서명   (Sign Message)
  3. 서명 검증     (Verify)
  4. 파일 서명     (Sign File)
  0. 종료          (Exit)
─────────────────────────────────────
>
```

> For each key/signature prompt, you can enter either a **file path** or **paste PEM directly**.

### Example: Full Flow

```bash
# 1. Generate key pair → saves mykey.pub / mykey.priv
> 1
저장할 이름: mykey

# 2. Sign a message → saves sig.pem
> 2
비밀키: mykey.priv
메시지: Hello, HASA!
저장 경로: sig.pem

# 3. Verify
> 3
공개키: mykey.pub
서명: sig.pem
방식: m
메시지: Hello, HASA!
→ [결과] ✓ 검증 성공 (OK)

# 4. Sign a file → saves document.txt.sig
> 4
비밀키: mykey.priv
파일: document.txt
```

---

## 📦 Library Usage

Add `HASA_17.jar` to your classpath.

```java
import com.hasa.crypto.HASA;
import com.hasa.crypto.HASAPemCodec;

// Generate key pair
HASA.KeyPair kp = HASA.genKey();

// Sign
byte[] msg = "Hello, HASA!".getBytes("UTF-8");
HASA.Signature sig = HASA.sign(msg, kp);

// Verify
boolean ok = HASA.verify(msg, sig.R, sig.s, kp.Q);
System.out.println(ok); // true

// Encode to PEM
String pubPem = HASAPemCodec.encodePublicKey(kp.Q);
String sigPem = HASAPemCodec.encodeSignature(sig);

// Decode from PEM
ECPoint pub       = HASAPemCodec.decodePublicKey(pubPem);
HASA.Signature s  = HASAPemCodec.decodeSignature(sigPem);
```

---

## 🔐 PEM Format

**Public Key**
```
-----BEGIN HASA PUBLIC KEY-----
A4D9D28hP+v4x5TN6/6UcJ/Hrnyk39YmEarW3gLmKK+i
-----END HASA PUBLIC KEY-----
```

**Private Key**
```
-----BEGIN HASA PRIVATE KEY-----
xiP0cExqCoqriqcZmr+cU7iVaKde7Hoph8+15r650IA=
-----END HASA PRIVATE KEY-----
```

**Signature**
```
-----BEGIN HASA SIGNATURE-----
A2jyrQ1RCWl3G8CodjzaczmjPbD17fg9OWWOFjNuKVPn5uw1+F0guJ54lLz7sDXH
mYDvsZ2Wn6p1qqc8plsLr6k=
-----END HASA SIGNATURE-----
```

---

## 🔧 Building from Source

```bash
# Compile all sources
javac -encoding UTF-8 \
  -cp lib/bcprov-jdk18on-1.84.jar \
  -d bin \
  src/main/java/com/hasa/crypto/*.java

# Package library JAR (no Main class)
jar cf HASA_17.jar -C bin .

# Package executable JAR
jar cfe HASA_EXE.jar com.hasa.crypto.Main -C bin .
```

> **Fat JAR tip:** When bundling Bouncy Castle, extract its JAR and remove `META-INF/*.SF` and `META-INF/*.RSA` signature files before repackaging to avoid `SecurityException`.

---

## 🤝 Contributing

Security reviews, bug reports, and improvements are very welcome!
See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

---

## 🤖 AI Assistance

This project was developed with the assistance of **[Claude](https://claude.ai)** (Anthropic's AI).  
Claude helped design the CLI architecture, debug JAR packaging issues, and write documentation.

---

## 📄 License

MIT — see [LICENSE](../LICENSE).
