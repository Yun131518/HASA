# HASA Formal Security Proof

## 1. 스킴 정의

**파라미터**

- `G` — secp256k1 기저점 (생성원)
- `n` — G의 위수 (`n`은 소수)
- 해시 함수 `H = tagHash("CHALLENGE-V1", ·)` — SHA-256 기반 태그 해시

**키 생성**
```
d ←ᴿ [1, n−1]
Q = d·G
```

**서명** `Sign(d, m)`
```
k = NONCE-V1(d, m)     // 결정론적 논스, k ∈ [1, n−1]
R = k·G
e = H(R ‖ Q ‖ SHA256(m)) mod n
if e = 0: e ← 1        // e ≠ 0 강제
s = (k + e·d) mod n
if s = 0: k 재생성      // s ≠ 0 강제
return (R, s)
```

**검증** `Verify(Q, m, R, s)`
```
check: s ∈ [1, n−1]
check: R ≠ ∞, R ∈ curve
check: Q ≠ ∞, Q ∈ curve
e = H(R ‖ Q ‖ SHA256(m)) mod n
if e = 0: e ← 1
return G·s == R + Q·e
```

---

## 2. 보안 정의

**정의 2.1 (EUF-CMA)**

서명 스킴 Σ = (KeyGen, Sign, Verify) 가 적응적 선택 메시지 공격에 대해 존재적 위조 불가능(EUF-CMA)하다는 것은, 다항 시간 적대자 𝒜가 서명 오라클에 접근하더라도 이전에 서명 요청을 한 적 없는 메시지 m*에 대한 유효한 서명 (R*, s*)을 출력할 수 없다는 것이다.

**정의 2.2 (ECDLP)**

타원 곡선 이산 대수 문제(ECDLP): 주어진 Q = d·G에서 d를 구하는 것이 계산적으로 불가능하다.

**정의 2.3 (ROM — Random Oracle Model)**

`tagHash("CHALLENGE-V1", ·)` 를 완전 랜덤 함수로 모델링한다.

---

## 3. 정리 (보안 환원)

**정리 3.1**

H를 랜덤 오라클로 모델링하면, HASA는 ECDLP 어려움 가정 하에 EUF-CMA 안전하다.

더 정확하게:

$$\text{Adv}^{\text{EUF-CMA}}_{\text{HASA}}(\mathcal{A}) \leq \frac{q_s^2}{n} + \frac{q_h \cdot \text{Adv}^{\text{ECDLP}}(\mathcal{B})}{\text{poly}}$$

여기서 `q_s` = 서명 쿼리 수, `q_h` = 해시 쿼리 수.

---

## 4. 증명 (Forking Lemma 기반 환원)

**목표:** EUF-CMA 위조자 𝒜로부터 ECDLP 풀이자 ℬ를 구성한다.

### 4.1 시뮬레이션 구성

ℬ는 ECDLP 인스턴스 Q = d·G를 받는다. 목표는 d를 구하는 것이다.

ℬ는 다음과 같이 𝒜를 시뮬레이션한다:

1. **공개키:** Q를 𝒜에게 공개키로 제공한다.

2. **서명 오라클 시뮬레이션 — 프로그래밍 기법:**
   - 서명 요청 m_i에 대해:
     - `s_i ←ᴿ [1, n−1]`, `e_i ←ᴿ [1, n−1]` 를 무작위로 선택
     - `R_i = G·s_i − Q·e_i` 를 계산
     - 랜덤 오라클 H(R_i ‖ Q ‖ H(m_i))의 출력을 `e_i`로 프로그래밍
     - `(R_i, s_i)` 반환
   - 검증: `G·s_i = R_i + Q·e_i` ✓ — 유효한 서명이다.
   - 비밀 키 d 없이 서명 생성 가능.

3. **위조 출력:** 𝒜가 (m*, R*, s*)를 출력한다.

### 4.2 Forking Lemma 적용

Forking Lemma (Bellare–Neven 2006)에 의해, 𝒜가 성공 확률 ε을 가지면:

ℬ는 동일한 초기 랜덤 테이프를 사용하되 H의 해시 응답을 다르게 설정하여 두 번의 실행으로:

- 실행 1: H(R* ‖ Q ‖ H(m*)) = e*₁ → (R*, s*₁) 획득
- 실행 2: H(R* ‖ Q ‖ H(m*)) = e*₂ → (R*, s*₂) 획득

둘 다 유효한 서명이면:

```
G·s*₁ = R* + Q·e*₁
G·s*₂ = R* + Q·e*₂
```

뺄셈:

```
G·(s*₁ − s*₂) = Q·(e*₁ − e*₂)
G·(s*₁ − s*₂) = d·G·(e*₁ − e*₂)
```

`e*₁ ≠ e*₂` (ROM에서 독립적으로 선택) 이므로 `(e*₁ − e*₂)` 는 mod n에서 역원이 존재하며:

```
d = (s*₁ − s*₂) · (e*₁ − e*₂)⁻¹ mod n
```

**결론:** ℬ는 ECDLP를 풀었다. ∎

---

## 5. 추가 안전성 속성 증명

### 5.1 논스 재사용 불가 (결정론성으로 방지)

**명제 5.1:** 동일한 (d, m) 쌍에 대해 논스 k는 항상 동일하다.

**증명:** `k = tagHash("NONCE-V1", d ‖ m ‖ 0x00000000)` 는 결정론적 함수다.
k가 무효(`k < 1` 또는 `k ≥ n`)면 counter를 1씩 증가시키며 재계산한다.
따라서 k는 결정론적으로 유일하다. ∎

**명제 5.2 (논스 재사용 시 키 복구):** 두 메시지 m₁ ≠ m₂에 대해 같은 k를 사용하면:
```
s₁ = k + e₁·d,  s₂ = k + e₂·d
s₁ − s₂ = (e₁ − e₂)·d  →  d = (s₁ − s₂)/(e₁ − e₂) mod n
```
→ HASA는 결정론적 논스로 이를 원천 방지한다.

### 5.2 도메인 분리 (태그 해시)

**명제 5.3:** `tagHash("NONCE-V1", ·)` 와 `tagHash("CHALLENGE-V1", ·)` 는 충돌하지 않는다.

**증명:** BIP340 패턴을 따라, 입력 바이트열 앞에 `SHA256(tag) ‖ SHA256(tag)` (64바이트) 를 prepend한다.
두 태그의 SHA256 값이 다르므로 입력 공간이 완전히 분리된다.
ROM 모델에서 이는 두 개의 독립된 랜덤 오라클로 취급된다. ∎

### 5.3 challenge e = 0 처리

**명제 5.4:** `e ← 1` 대체가 보안을 약화시키지 않는다.

**증명:** `H(R ‖ Q ‖ H(m)) = 0 mod n` 의 확률은 `1/n ≈ 2⁻²⁵⁶` 이므로 무시 가능하다.
`e = 0`일 때 대체하면 `s = k`가 되어 비밀 키가 직접 노출될 수 있으므로 방어적으로 `e ← 1`로 치환한다.
이 치환은 위조자에게 이점을 주지 않는다 — 위조자가 H의 출력을 0으로 만들려면 SHA256 preimage를 찾아야 한다. ∎

### 5.4 s = 0 거부

**명제 5.5:** `s = 0` 서명은 검증에서 거부된다.

**증명:** 검증 조건 `s ∈ [1, n−1]` 에 의해 `s = 0`은 즉시 거부.
생성 시에도 `s = 0`이면 재생성하므로 유효한 서명에서 절대 발생하지 않는다. ∎

### 5.5 스칼라 블라인딩 (타이밍 공격 방어)

**명제 5.6:** `d_blind = d + r·n` 블라인딩이 함수적으로 동일하다.

**증명:**
```
s = k + e·d_blind mod n
  = k + e·(d + r·n) mod n
  = k + e·d + e·r·n mod n
  = k + e·d mod n           ∵ e·r·n ≡ 0 (mod n)
```
따라서 블라인딩은 mod n 결과를 변경하지 않는다. ∎

---

## 6. 입력 검증 속성 (구현 수준)

다음 속성들은 `verify()` 함수에서 구현으로 보장된다:

| 조건 | 코드 | 근거 |
|---|---|---|
| `s ∈ [1, n−1]` | `s.signum() <= 0 \|\| s.compareTo(n) >= 0` | 범위 외 s는 ECDLP 관련 없는 쓰레기값 |
| `R ≠ ∞` | `R.isInfinity()` | 무한점 R → e 계산 시 좌표 압축 실패 |
| `R ∈ curve` | `R.isValid()` | 곡선 외 점은 위조 가능 |
| `Q ≠ ∞` | `Q.isInfinity()` | Q = ∞ 이면 s = k 만으로 서명 위조 |
| `Q ∈ curve` | `Q.isValid()` | 위와 동일 |
| `decodePublicKey` 33바이트 | 길이 검사 | AIOBE 방지 (Jazzer로 발견) |
| `decodeSignature` 65바이트 | 길이 검사 | 파싱 에러 방지 |

---

## 7. 잔여 위험 및 한계

| 항목 | 상태 | 설명 |
|---|---|---|
| Java `BigInteger` 타이밍 | **부분 완화** | libsecp256k1 JNA 사용 시 상수시간; fallback Java에서는 스칼라 블라인딩으로 완화 |
| GLV 최적화 | **완화** | `CustomNamedCurves` 사용으로 256비트 → ~128비트 스칼라로 EC 타이밍 노출 절반 감소 |
| 사이드채널 (캐시, 전력) | **미완화** | JVM 환경에서 JIT 최적화에 의존; 고위험 HSM 환경에서는 추가 하드웨어 방어 필요 |
| 양자 저항성 | **없음** | secp256k1은 Shor 알고리즘에 취약; 양자 내성 스킴 필요 시 별도 교체 |
| 형식 도구 검증 | **미완료** | EasyCrypt/CryptoVerif 모델 코딩 필요 (ROM 하에서 기계 검증 가능) |

---

## 8. 참고 문헌

1. Pointcheval, D. & Stern, J. (1996). "Security Proofs for Signature Schemes." *EUROCRYPT 1996*.
2. Bellare, M. & Neven, G. (2006). "Multi-signatures in the plain public-key model and a general forking lemma." *CCS 2006*.
3. BIP340 — Schnorr Signatures for secp256k1. Bitcoin Core.
4. Brown, D.R.L. (2016). "SEC 2: Recommended Elliptic Curve Domain Parameters." *SECG*.
5. Bernstein, D.J. & Lange, T. (2017). "Montgomery curves and the Montgomery ladder." *IACR*.
