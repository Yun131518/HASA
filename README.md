# HASA

**HASA** is a digital signature library built on the **secp256k1** elliptic curve (the same curve used in Bitcoin), powered by [Bouncy Castle](https://www.bouncycastle.org/).

It implements a custom Schnorr-style signature scheme with deterministic nonce generation.

---

## Features

- secp256k1 elliptic curve key pair generation
- Deterministic nonce (`NONCE-V1` tag hash)
- Schnorr-style signing and verification
- PEM encoding/decoding for public keys and signatures
- Interactive CLI tool (`HASA_EXE.jar`)

---

## Project Structure

```
HASA/
├── src/main/java/com/hasa/crypto/
│   ├── HASA.java          # Core: key generation, sign, verify
│   ├── HASAPemCodec.java  # PEM encode/decode for keys and signatures
│   └── Main.java          # Interactive CLI tool
├── lib/
│   └── bcprov-jdk18on-1.84.jar   # Bouncy Castle dependency
├── HASA_17.jar            # Library JAR (Java 17, fat JAR)
└── HASA_EXE.jar           # Executable CLI JAR (Java 17, fat JAR)
```

---

## Requirements

- Java 17+

---

## CLI Usage

Run the interactive tool:

```bash
java -jar HASA_EXE.jar
```

```
╔══════════════════════════════════════╗
║   HASA CLI - secp256k1 서명 도구     ║
╚══════════════════════════════════════╝

─────────────────────────────────────
  1. 키페어 생성
  2. 메시지 서명
  3. 서명 검증
  4. 파일 서명
  0. 종료
─────────────────────────────────────
```

### 1. Key Pair Generation

Enter a name to save to files, or press Enter to print only.

```
저장할 이름 (Enter = 화면 출력만): mykey
→ mykey.pub / mykey.priv saved
```

### 2. Sign a Message

Accepts a file path **or** inline PEM paste for the private key.

```
비밀키 (파일 경로 또는 PEM 직접 입력): mykey.priv
서명할 메시지: Hello, HASA!
서명 저장 경로 (Enter = 화면 출력만): sig.pem
```

### 3. Verify a Signature

Supports message or file (`f`) verification. Public key and signature accept file path or inline PEM.

```
공개키 (파일 경로 또는 PEM 직접 입력): mykey.pub
서명 (파일 경로 또는 PEM 직접 입력): sig.pem
검증 방식 - 메시지(m) / 파일(f): m
메시지: Hello, HASA!
→ [결과] ✓ 검증 성공 (OK)
```

### 4. Sign a File

Loads a file's raw bytes and signs them. Saves the signature as `<file>.sig`.

```
비밀키 (파일 경로 또는 PEM 직접 입력): mykey.priv
서명할 파일 경로: document.txt
서명 저장 경로 (Enter = <파일>.sig):
→ document.txt.sig saved
```

---

## Library Usage

Add `HASA_17.jar` to your classpath.

```java
// Key generation
HASA.KeyPair kp = HASA.genKey();

// Sign
byte[] msg = "Hello".getBytes("UTF-8");
HASA.Signature sig = HASA.sign(msg, kp);

// Verify
boolean ok = HASA.verify(msg, sig.R, sig.s, kp.Q);

// PEM encode
String pubPem = HASAPemCodec.encodePublicKey(kp.Q);
String sigPem = HASAPemCodec.encodeSignature(sig);

// PEM decode
ECPoint pub = HASAPemCodec.decodePublicKey(pubPem);
HASA.Signature decoded = HASAPemCodec.decodeSignature(sigPem);
```

---

## PEM Format

**Public Key**
```
-----BEGIN HASA PUBLIC KEY-----
A4D9D28hP+v4x5TN6/6UcJ/Hrnyk39YmEarW3gLmKK+i
-----END HASA PUBLIC KEY-----
```

**Signature**
```
-----BEGIN HASA SIGNATURE-----
A2jyrQ1RCWl3G8CodjzaczmjPbD17fg9OWWOFjNuKVPn5uw1+F0guJ54lLz7sDXH
mYDvsZ2Wn6p1qqc8plsLr6k=
-----END HASA SIGNATURE-----
```

---

## Building from Source

```bash
# Compile
javac -encoding UTF-8 -cp lib/bcprov-jdk18on-1.84.jar \
  -d bin src/main/java/com/hasa/crypto/*.java

# Library JAR (no Main)
jar cf HASA_17.jar -C bin .

# Executable JAR
jar cfe HASA_EXE.jar com.hasa.crypto.Main -C bin .
```

> Note: For fat JARs (dependencies included), extract `bcprov-jdk18on-1.84.jar` and remove its signature files (`META-INF/*.SF`, `*.RSA`) before repackaging.

---

## License

MIT — see [LICENSE](LICENSE).
