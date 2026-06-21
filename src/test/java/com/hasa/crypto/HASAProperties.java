package com.hasa.crypto;

import net.jqwik.api.*;
import net.jqwik.api.constraints.*;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * jqwik 기반 property-based 테스트 (경량 퍼징).
 *
 * jqwik는 각 property를 수백~수천 회 무작위 입력으로 실행한다.
 * 실패하는 케이스를 발견하면 최소 재현 케이스로 shrink해서 리포트한다.
 *
 * pom.xml: jqwik.tries=500 (기본값; -Djqwik.tries=N 으로 조정 가능)
 */
class HASAProperties {

    // ── 서명/검증 라운드트립 ──────────────────────────────────────

    @Property
    @Label("임의 메시지: sign→verify 항상 성공")
    void prop_signVerify_anyMessage(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q));
    }

    @Property
    @Label("임의 UTF-8 문자열: sign→verify 항상 성공")
    void prop_signVerify_utf8(@ForAll @StringLength(max = 10000) String text) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q));
    }

    // ── 위조 불가 ────────────────────────────────────────────────

    @Property
    @Label("메시지 1바이트 변조 시 검증 실패")
    void prop_oneByteFlip_fails(
            @ForAll @Size(min = 1, max = 512) byte[] msg,
            @ForAll @IntRange(min = 0, max = 255) int flipByte) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature sig = HASA.sign(msg, kp);

        byte[] tampered = msg.clone();
        tampered[0] ^= (byte)(flipByte | 1); // 최소 1비트는 뒤집음
        if (java.util.Arrays.equals(tampered, msg)) return; // 혹시 동일하면 스킵

        assertFalse(HASA.verify(tampered, sig.R, sig.s, kp.Q));
    }

    @Property
    @Label("다른 키페어의 공개키로는 검증 실패")
    void prop_wrongKey_fails(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair signer   = HASA.genKey();
        HASA.KeyPair imposter = HASA.genKey();
        HASA.Signature sig = HASA.sign(msg, signer);
        assertFalse(HASA.verify(msg, sig.R, sig.s, imposter.Q));
    }

    // ── 논스 유일성 ──────────────────────────────────────────────

    @Property
    @Label("서로 다른 메시지는 서로 다른 논스를 생성")
    void prop_nonce_uniquePerMessage(
            @ForAll byte[] msg1,
            @ForAll byte[] msg2) throws Exception {
        Assume.that(!java.util.Arrays.equals(msg1, msg2));
        HASA.KeyPair kp = HASA.genKey();
        BigInteger k1 = HASA.nonce(kp.privateKey(), msg1);
        BigInteger k2 = HASA.nonce(kp.privateKey(), msg2);
        assertNotEquals(k1, k2);
    }

    @Property
    @Label("논스는 항상 [1, n) 범위")
    void prop_nonce_inRange(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        BigInteger k = HASA.nonce(kp.privateKey(), msg);
        assertTrue(k.compareTo(BigInteger.ONE) >= 0);
        assertTrue(k.compareTo(HASA.n) < 0);
    }

    // ── 서명 s 범위 ──────────────────────────────────────────────

    @Property
    @Label("서명 s는 항상 [1, n) 범위")
    void prop_sig_sInRange(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(sig.s.compareTo(BigInteger.ONE) >= 0, "s < 1");
        assertTrue(sig.s.compareTo(HASA.n) < 0,          "s >= n");
    }

    // ── 결정론성 ─────────────────────────────────────────────────

    @Property
    @Label("같은 (key, msg) 쌍은 항상 같은 서명 생성")
    void prop_sign_deterministic(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature s1 = HASA.sign(msg, kp);
        HASA.Signature s2 = HASA.sign(msg, kp);
        assertEquals(s1.R.normalize(), s2.R.normalize());
        assertEquals(s1.s, s2.s);
    }

    // ── PEM 라운드트립 ───────────────────────────────────────────

    @Property
    @Label("임의 메시지: 서명 PEM 인코딩→디코딩→검증 성공")
    void prop_pem_signatureRoundTrip(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature sig = HASA.sign(msg, kp);

        String pem = HASAPemCodec.encodeSignature(sig);
        HASA.Signature decoded = HASAPemCodec.decodeSignature(pem);
        assertTrue(HASA.verify(msg, decoded.R, decoded.s, kp.Q));
    }

    @Property
    @Label("공개키 PEM 인코딩→디코딩 후 서명 검증 성공")
    void prop_pem_publicKeyRoundTrip(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature sig = HASA.sign(msg, kp);

        ECPoint decoded = HASAPemCodec.decodePublicKey(HASAPemCodec.encodePublicKey(kp.Q));
        assertTrue(HASA.verify(msg, sig.R, sig.s, decoded));
    }

    // ── challenge 비제로 ─────────────────────────────────────────

    @Property
    @Label("challenge는 절대 0을 반환하지 않음")
    void prop_challenge_neverZero(@ForAll byte[] msg) throws Exception {
        HASA.KeyPair kp = HASA.genKey();
        BigInteger k = HASA.nonce(kp.privateKey(), msg);
        ECPoint R = HASA.G.multiply(k).normalize();
        BigInteger e = HASA.challenge(R, kp.Q, msg);
        assertNotEquals(BigInteger.ZERO, e);
    }

    // ── 잘못된 서명 길이 거부 ────────────────────────────────────

    @Property
    @Label("65바이트가 아닌 임의 바이트는 decodeSignature에서 예외 발생")
    void prop_decodeSignature_rejectsWrongLength(
            @ForAll @Size(min = 0, max = 128) byte[] payload) throws Exception {
        if (payload.length == 65) return; // 65바이트는 올바른 케이스
        String b64 = org.bouncycastle.util.encoders.Base64.toBase64String(payload);
        String pem = "-----BEGIN HASA SIGNATURE-----\n" + b64 + "\n-----END HASA SIGNATURE-----\n";
        assertThrows(Exception.class, () -> HASAPemCodec.decodeSignature(pem));
    }
}
