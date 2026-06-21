package com.hasa.crypto;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HASA 핵심 암호화 로직 단위 테스트.
 *
 * 커버 범위:
 *  - 정상 서명 / 검증 라운드트립
 *  - 변조 감지 (메시지 / 키 / 서명)
 *  - 논스 결정론성
 *  - 입력 경계값 거부
 *  - 태그 해시 도메인 분리
 *  - 100회 연속 서명 (회귀 방지)
 */
class HASATest {

    // ── 키페어 생성 ──────────────────────────────────────────────

    @Test
    void genKey_publicKeyOnCurve() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        assertFalse(kp.Q.isInfinity(), "공개키가 무한점이어서는 안 됨");
        assertTrue(kp.Q.isValid(),     "공개키가 곡선 위에 있어야 함");
    }

    @Test
    void genKey_differentEachCall() throws Exception {
        HASA.KeyPair kp1 = HASA.genKey();
        HASA.KeyPair kp2 = HASA.genKey();
        assertNotEquals(kp1.Q, kp2.Q, "두 키페어는 달라야 함");
    }

    // ── 서명 / 검증 라운드트립 ───────────────────────────────────

    @Test
    void signVerify_success() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "Hello HASA".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q));
    }

    @Test
    void signVerify_emptyMessage() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature sig = HASA.sign(new byte[0], kp);
        assertTrue(HASA.verify(new byte[0], sig.R, sig.s, kp.Q));
    }

    @Test
    void signVerify_singleByte() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = {0x00};
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q));
    }

    @Test
    void signVerify_largeMessage_1MB() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = new byte[1024 * 1024];
        new java.util.Random(0xCAFE).nextBytes(msg);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "a", "한국어 메시지", "0x0000ff", "!@#$%^&*()"})
    void signVerify_variousMessages(String text) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q));
    }

    // ── 변조 감지 ────────────────────────────────────────────────

    @Test
    void verify_fails_tamperedMessage() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] orig = "original".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(orig, kp);
        byte[] tampered = "tampered!".getBytes(StandardCharsets.UTF_8);
        assertFalse(HASA.verify(tampered, sig.R, sig.s, kp.Q));
    }

    @Test
    void verify_fails_wrongPublicKey() throws Exception {
        HASA.KeyPair kp1 = HASA.genKey();
        HASA.KeyPair kp2 = HASA.genKey();
        byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp1);
        assertFalse(HASA.verify(msg, sig.R, sig.s, kp2.Q));
    }

    @Test
    void verify_fails_flippedBitInMessage() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "bitflip test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        byte[] flipped = Arrays.copyOf(msg, msg.length);
        flipped[0] ^= 0x01; // 첫 바이트 1비트 반전
        assertFalse(HASA.verify(flipped, sig.R, sig.s, kp.Q));
    }

    @Test
    void verify_fails_modifiedS() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        BigInteger badS = sig.s.add(BigInteger.ONE).mod(HASA.n);
        assertFalse(HASA.verify(msg, sig.R, badS, kp.Q));
    }

    @Test
    void verify_fails_modifiedR() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        ECPoint badR = HASA.G.multiply(BigInteger.TWO).normalize();
        assertFalse(HASA.verify(msg, badR, sig.s, kp.Q));
    }

    // ── 입력값 경계 거부 ─────────────────────────────────────────

    @Test
    void verify_rejects_nullR() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        assertFalse(HASA.verify(msg, null, BigInteger.ONE, kp.Q));
    }

    @Test
    void verify_rejects_infinityR() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        ECPoint inf = HASA.domain.getCurve().getInfinity();
        assertFalse(HASA.verify(msg, inf, BigInteger.ONE, kp.Q));
    }

    @Test
    void verify_rejects_nullQ() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertFalse(HASA.verify(msg, sig.R, sig.s, null));
    }

    @Test
    void verify_rejects_infinityQ() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        ECPoint inf = HASA.domain.getCurve().getInfinity();
        assertFalse(HASA.verify(msg, sig.R, sig.s, inf));
    }

    @Test
    void verify_rejects_sZero() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertFalse(HASA.verify(msg, sig.R, BigInteger.ZERO, kp.Q));
    }

    @Test
    void verify_rejects_sEqualsN() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertFalse(HASA.verify(msg, sig.R, HASA.n, kp.Q));
    }

    @Test
    void verify_rejects_sNegative() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertFalse(HASA.verify(msg, sig.R, BigInteger.ONE.negate(), kp.Q));
    }

    // ── 논스 결정론성 ────────────────────────────────────────────

    @Test
    void nonce_isDeterministic_sameInputs() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "determinism".getBytes(StandardCharsets.UTF_8);
        BigInteger k1 = HASA.nonce(kp.privateKey(), msg);
        BigInteger k2 = HASA.nonce(kp.privateKey(), msg);
        assertEquals(k1, k2);
    }

    @Test
    void nonce_differs_differentMessages() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        BigInteger k1 = HASA.nonce(kp.privateKey(), "msg1".getBytes(StandardCharsets.UTF_8));
        BigInteger k2 = HASA.nonce(kp.privateKey(), "msg2".getBytes(StandardCharsets.UTF_8));
        assertNotEquals(k1, k2);
    }

    @Test
    void nonce_inRange_1_to_nMinus1() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        for (int i = 0; i < 20; i++) {
            byte[] msg = ("seed" + i).getBytes(StandardCharsets.UTF_8);
            BigInteger k = HASA.nonce(kp.privateKey(), msg);
            assertTrue(k.compareTo(BigInteger.ONE) >= 0, "k >= 1 위반");
            assertTrue(k.compareTo(HASA.n) < 0,          "k < n 위반");
        }
    }

    @Test
    void sign_isDeterministic() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = "same message".getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig1 = HASA.sign(msg, kp);
        HASA.Signature sig2 = HASA.sign(msg, kp);
        assertEquals(sig1.R.normalize(), sig2.R.normalize(), "R이 달라짐");
        assertEquals(sig1.s, sig2.s, "s가 달라짐");
    }

    // ── 태그 해시 도메인 분리 ────────────────────────────────────

    @Test
    void tagHash_domainSeparation() throws Exception {
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);
        byte[] h1 = HASA.tagHash("NONCE-V1",     data);
        byte[] h2 = HASA.tagHash("CHALLENGE-V1", data);
        assertFalse(Arrays.equals(h1, h2), "태그가 다르면 해시도 달라야 함");
    }

    @Test
    void challenge_isNonZero() throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        ECPoint R = HASA.G.multiply(BigInteger.TWO).normalize();
        BigInteger e = HASA.challenge(R, kp.Q, "x".getBytes(StandardCharsets.UTF_8));
        assertNotEquals(BigInteger.ZERO, e, "challenge가 0이어서는 안 됨");
    }

    // ── 회귀 방지: 100회 연속 서명 ──────────────────────────────

    @Test
    @DisplayName("100회 연속 keygen→sign→verify 성공")
    void regression_100rounds() throws Exception {
        for (int i = 0; i < 100; i++) {
            HASA.KeyPair kp = HASA.genKey();
            byte[] msg = ("round-" + i).getBytes(StandardCharsets.UTF_8);
            HASA.Signature sig = HASA.sign(msg, kp);
            assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q),
                       "라운드 " + i + " 검증 실패");
        }
    }

    // ── 서명 s 범위 ─────────────────────────────────────────────

    @Test
    void sign_sIsInRange() throws Exception {
        for (int i = 0; i < 20; i++) {
            HASA.KeyPair kp = HASA.genKey();
            byte[] msg = ("range-" + i).getBytes(StandardCharsets.UTF_8);
            HASA.Signature sig = HASA.sign(msg, kp);
            assertTrue(sig.s.compareTo(BigInteger.ONE) >= 0, "s >= 1 위반");
            assertTrue(sig.s.compareTo(HASA.n) < 0,          "s < n 위반");
        }
    }
}
