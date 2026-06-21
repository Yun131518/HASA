<div align="center">

# ⚡ HASA

**Java용 경량 secp256k1 디지털 서명 라이브러리 & CLI 도구**

![Java](https://img.shields.io/badge/Java-17%2B-orange?style=for-the-badge&logo=openjdk)
![Curve](https://img.shields.io/badge/Curve-secp256k1-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![BouncyCastle](https://img.shields.io/badge/BouncyCastle-1.84-purple?style=for-the-badge)

**한국어** | [English](README_EN.md)

</div>

---

## 📖 HASA란?

**HASA**는 비트코인, 이더리움에서도 사용하는 **secp256k1** 타원곡선 기반의 디지털 서명 라이브러리입니다.  
[Bouncy Castle](https://www.bouncycastle.org/)을 기반으로 커스텀 **Schnorr 스타일 서명 체계**를 구현합니다.

주요 설계 특징:
- 태그 해시 함수로 도메인 분리 (`NONCE-V1`, `CHALLENGE-V1`)
- 결정론적 논스 생성 (랜덤 k 유출 위험 없음)
- PEM 형식으로 키와 서명을 사람이 읽기 쉽게 인코딩

> ⚠️ **주의:** HASA는 교육 및 연구 목적의 커스텀 암호화 체계입니다. 보안 감사를 거치지 않았으므로 **프로덕션 환경에서는 사용하지 마세요.** 기여와 보안 리뷰를 적극 환영합니다!

---

## ✨ 기능

| 기능 | 설명 |
|---|---|
| 🔑 키페어 생성 | secp256k1 공개키/비밀키 쌍 생성 |
| ✍️ 서명 | Schnorr 스타일 결정론적 서명 |
| ✅ 검증 | 서명 유효성 검증 |
| 📄 파일 서명 | 파일의 원시 바이트로 서명 |
| 🔒 PEM 코덱 | 키와 서명을 PEM 형식으로 인코딩/디코딩 |
| 💻 CLI 도구 | 인터랙티브 터미널 인터페이스 |

---

## 📁 프로젝트 구조

```
HASA/
├── src/main/java/com/hasa/crypto/
│   ├── HASA.java           # 핵심: 키 생성, 서명, 검증, 해시
│   ├── HASAPemCodec.java   # PEM 인코딩/디코딩
│   └── Main.java           # 인터랙티브 CLI
├── lib/
│   └── bcprov-jdk18on-1.84.jar   # Bouncy Castle 의존성
├── readme/
│   ├── README_EN.md        # 영어 버전
│   └── README_KO.md        # 이 파일
├── HASA_17.jar             # 라이브러리 JAR (Java 17, fat JAR)
├── HASA_EXE.jar            # 실행형 CLI JAR (Java 17, fat JAR)
├── CONTRIBUTING.md
└── LICENSE
```

---

## 🚀 시작하기

### 요구사항
- Java 17 이상

### 다운로드

저장소 루트에서 JAR 파일을 받으세요:

| 파일 | 용도 |
|---|---|
| `HASA_17.jar` | 라이브러리로 클래스패스에 추가 |
| `HASA_EXE.jar` | 단독 CLI 도구로 실행 |

---

## 💻 CLI 사용법

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
>
```

> 키/서명 입력 시 **파일 경로** 또는 **PEM 직접 붙여넣기** 모두 가능합니다.

### 예시: 전체 흐름

```bash
# 1. 키페어 생성 → mykey.pub / mykey.priv 저장
> 1
저장할 이름: mykey

# 2. 메시지 서명 → sig.pem 저장
> 2
비밀키: mykey.priv
메시지: Hello, HASA!
저장 경로: sig.pem

# 3. 서명 검증
> 3
공개키: mykey.pub
서명: sig.pem
방식: m
메시지: Hello, HASA!
→ [결과] ✓ 검증 성공 (OK)

# 4. 파일 서명 → document.txt.sig 저장
> 4
비밀키: mykey.priv
파일: document.txt
```

---

## 📦 라이브러리 사용법

`HASA_17.jar`을 클래스패스에 추가하세요.

```java
import com.hasa.crypto.HASA;
import com.hasa.crypto.HASAPemCodec;

// 키페어 생성
HASA.KeyPair kp = HASA.genKey();

// 서명
byte[] msg = "Hello, HASA!".getBytes("UTF-8");
HASA.Signature sig = HASA.sign(msg, kp);

// 검증
boolean ok = HASA.verify(msg, sig.R, sig.s, kp.Q);
System.out.println(ok); // true

// PEM 인코딩
String pubPem = HASAPemCodec.encodePublicKey(kp.Q);
String sigPem = HASAPemCodec.encodeSignature(sig);

// PEM 디코딩
ECPoint pub       = HASAPemCodec.decodePublicKey(pubPem);
HASA.Signature s  = HASAPemCodec.decodeSignature(sigPem);
```

---

## 🔐 PEM 형식

**공개키**
```
-----BEGIN HASA PUBLIC KEY-----
A4D9D28hP+v4x5TN6/6UcJ/Hrnyk39YmEarW3gLmKK+i
-----END HASA PUBLIC KEY-----
```

**비밀키**
```
-----BEGIN HASA PRIVATE KEY-----
xiP0cExqCoqriqcZmr+cU7iVaKde7Hoph8+15r650IA=
-----END HASA PRIVATE KEY-----
```

**서명**
```
-----BEGIN HASA SIGNATURE-----
A2jyrQ1RCWl3G8CodjzaczmjPbD17fg9OWWOFjNuKVPn5uw1+F0guJ54lLz7sDXH
mYDvsZ2Wn6p1qqc8plsLr6k=
-----END HASA SIGNATURE-----
```

---

## 🔧 소스 빌드

```bash
# 전체 소스 컴파일
javac -encoding UTF-8 \
  -cp lib/bcprov-jdk18on-1.84.jar \
  -d bin \
  src/main/java/com/hasa/crypto/*.java

# 라이브러리 JAR (Main 제외)
jar cf HASA_17.jar -C bin .

# 실행형 JAR
jar cfe HASA_EXE.jar com.hasa.crypto.Main -C bin .
```

> **Fat JAR 주의:** Bouncy Castle을 함께 패키징할 때 `META-INF/*.SF`, `META-INF/*.RSA` 서명 파일을 제거하지 않으면 `SecurityException`이 발생합니다.

---

## 🤝 기여하기

보안 리뷰, 버그 리포트, 개선 제안 모두 환영합니다!  
자세한 내용은 [CONTRIBUTING.md](../CONTRIBUTING.md)를 참고하세요.

---

## 🤖 AI 도움

이 프로젝트는 **[Claude](https://claude.ai)** (Anthropic의 AI)의 도움을 받아 개발되었습니다.  
CLI 구조 설계, JAR 패키징 디버깅, 문서 작성 등에 Claude가 함께했습니다.

---

## 📄 라이선스

MIT — [LICENSE](../LICENSE) 참고.
