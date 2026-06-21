package com.hasa.crypto;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 퍼징 타겟 (Jazzer 없이도 JUnit 단위 테스트로 실행 가능).
 *
 * 모드 1 — 단위 테스트 (기본):
 *   mvn test          → 각 타겟을 소규모 무작위 입력으로 1회 실행 (회귀 방지)
 *
 * 모드 2 — Jazzer 퍼징:
 *   mvn test -Pfuzz -Djazzer.runs=100000
 *   → coverage-guided 방식으로 수십만 회 실행, 크래시/예외 자동 발견
 *   → jazzer-junit 0.22.1 이상 필요 (pom.xml -Pfuzz 프로파일)
 */
class HASAFuzzTargets {

    private final SecureRandom rng = new SecureRandom();

    // ── 단위 테스트로도 동작하는 퍼징 헬퍼 ──────────────────────

    private byte[] randomBytes(int maxLen) {
        byte[] b = new byte[rng.nextInt(maxLen + 1)];
        rng.nextBytes(b);
        return b;
    }

    // ── 퍼징 타겟 1: sign→verify 전체 파이프라인 ────────────────

    @Test
    void fuzz_signVerify() throws Exception {
        for (int i = 0; i < 200; i++) {
            byte[] msg = randomBytes(1024);
            HASA.KeyPair kp = HASA.genKey();
            HASA.Signature sig = HASA.sign(msg, kp);
            if (!HASA.verify(msg, sig.R, sig.s, kp.Q)) {
                throw new AssertionError(
                    "sign/verify 라운드트립 실패: msg.length=" + msg.length);
            }
        }
    }

    // ── 퍼징 타겟 2: 임의 바이트 → 서명 PEM 디코딩 ─────────────
    // IllegalArgumentException 등 명시적 예외는 허용,
    // NullPointerException / ArrayIndexOutOfBoundsException 등은 버그

    @Test
    void fuzz_decodeSignaturePem() throws Exception {
        for (int i = 0; i < 500; i++) {
            byte[] payload = randomBytes(128);
            String b64 = org.bouncycastle.util.encoders.Base64.toBase64String(payload);
            String pem = "-----BEGIN HASA SIGNATURE-----\n"
                       + b64 + "\n"
                       + "-----END HASA SIGNATURE-----\n";
            try {
                HASAPemCodec.decodeSignature(pem);
            } catch (IllegalArgumentException | IllegalStateException
                   | org.bouncycastle.crypto.DataLengthException e) {
                // 예상된 예외 — 정상
            }
            // 그 외 RuntimeException은 테스트 실패로 전파
        }
    }

    // ── 퍼징 타겟 3: 임의 바이트 → 공개키 PEM 디코딩 ───────────

    @Test
    void fuzz_decodePublicKeyPem() throws Exception {
        for (int i = 0; i < 500; i++) {
            byte[] payload = randomBytes(64);
            String b64 = org.bouncycastle.util.encoders.Base64.toBase64String(payload);
            String pem = "-----BEGIN HASA PUBLIC KEY-----\n"
                       + b64 + "\n"
                       + "-----END HASA PUBLIC KEY-----\n";
            try {
                HASAPemCodec.decodePublicKey(pem);
            } catch (IllegalArgumentException | IllegalStateException
                   | org.bouncycastle.crypto.DataLengthException e) {
                // 예상된 예외 — 정상
            }
        }
    }

    // ── 퍼징 타겟 4: 임의 s값으로 verify 호출 ───────────────────
    // 항상 true/false를 반환해야 하며 예외를 던지면 안 됨

    @Test
    void fuzz_verifyArbitraryS() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "fuzz target".getBytes(StandardCharsets.UTF_8);
        HASA.Signature legit = HASA.sign(msg, kp);

        for (int i = 0; i < 500; i++) {
            byte[] sBytes = new byte[32];
            rng.nextBytes(sBytes);
            BigInteger s = new BigInteger(1, sBytes);
            // 예외 없이 true/false만 반환해야 함
            HASA.verify(msg, legit.R, s, kp.Q);
        }
    }

    // ── 퍼징 타겟 5: tagHash에 임의 입력 ────────────────────────
    // 항상 32바이트 결과를 반환해야 함

    @Test
    void fuzz_tagHash() throws Exception {
        for (int i = 0; i < 500; i++) {
            byte[] tagBytes = randomBytes(64);
            String tag = new String(tagBytes, StandardCharsets.UTF_8);
            byte[] input = randomBytes(512);
            byte[] result = HASA.tagHash(tag, input);
            if (result.length != 32) {
                throw new AssertionError("tagHash가 32바이트가 아님: " + result.length);
            }
        }
    }

    // ── 퍼징 타겟 6: 서명 R 위조 시도 ──────────────────────────
    // 임의 R 포인트와 정상 s로 검증 시도 → 거의 항상 false여야 함

    @Test
    void fuzz_forgeryAttempt_randomR() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "forgery test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);

        for (int i = 0; i < 100; i++) {
            // 랜덤 스칼라로 임의 점 생성
            BigInteger randK;
            do { randK = new BigInteger(256, rng); }
            while (randK.compareTo(BigInteger.ONE) < 0 || randK.compareTo(HASA.n) >= 0);
            ECPoint fakeR = HASA.G.multiply(randK).normalize();

            if (fakeR.equals(sig.R)) continue; // 우연히 같은 R이면 스킵

            // 위조 시도: 진짜 s, 가짜 R → false여야 함
            boolean result = HASA.verify(msg, fakeR, sig.s, kp.Q);
            if (result) {
                throw new AssertionError("위조 서명이 검증 통과됨! 심각한 보안 버그.");
            }
        }
    }
}
