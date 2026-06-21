package com.hasa.crypto;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import javax.crypto.AEADBadTagException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HASA-ECIES 암호화/복호화 단위 테스트.
 */
class HASAEciesTest {

    private HASA.KeyPair kp;
    private byte[] msg;

    @BeforeEach
    void setup() throws Exception {
        kp  = HASA.genKey();
        msg = "안녕하세요 HASA-ECIES!".getBytes(StandardCharsets.UTF_8);
    }

    // ── 기본 라운드트립 ──────────────────────────────────────────

    @Test
    void encryptDecrypt_roundTrip() throws Exception {
        byte[] ct    = HASA.encrypt(msg, kp.Q);
        byte[] plain = HASA.decrypt(ct, kp);
        assertArrayEquals(msg, plain);
    }

    @Test
    void encryptDecrypt_emptyMessage() throws Exception {
        byte[] ct    = HASA.encrypt(new byte[0], kp.Q);
        byte[] plain = HASA.decrypt(ct, kp);
        assertArrayEquals(new byte[0], plain);
    }

    @Test
    void encryptDecrypt_singleByte() throws Exception {
        byte[] ct    = HASA.encrypt(new byte[]{0x42}, kp.Q);
        byte[] plain = HASA.decrypt(ct, kp);
        assertArrayEquals(new byte[]{0x42}, plain);
    }

    @Test
    void encryptDecrypt_largeMessage_1MB() throws Exception {
        byte[] large = new byte[1024 * 1024];
        new java.util.Random(0xEC1E5).nextBytes(large);
        byte[] ct    = HASA.encrypt(large, kp.Q);
        byte[] plain = HASA.decrypt(ct, kp);
        assertArrayEquals(large, plain);
    }

    // ── 와이어 포맷 검증 ─────────────────────────────────────────

    @Test
    void ciphertext_minimumLength() throws Exception {
        byte[] ct = HASA.encrypt(new byte[0], kp.Q);
        // R(33) + nonce(12) + tag(16) = 61
        assertEquals(61, ct.length);
    }

    @Test
    void ciphertext_lengthGrowsWithPlaintext() throws Exception {
        byte[] ct10  = HASA.encrypt(new byte[10],  kp.Q);
        byte[] ct100 = HASA.encrypt(new byte[100], kp.Q);
        assertEquals(61 + 10,  ct10.length);
        assertEquals(61 + 100, ct100.length);
    }

    // ── 랜덤성: 같은 입력이어도 매번 다른 암호문 ────────────────

    @Test
    void encrypt_nonDeterministic() throws Exception {
        byte[] ct1 = HASA.encrypt(msg, kp.Q);
        byte[] ct2 = HASA.encrypt(msg, kp.Q);
        assertFalse(Arrays.equals(ct1, ct2), "에페머럴 키가 달라서 암호문도 달라야 함");
    }

    // ── 변조 감지 (GCM 태그) ────────────────────────────────────

    @Test
    void decrypt_fails_wrongKey() throws Exception {
        byte[] ct        = HASA.encrypt(msg, kp.Q);
        HASA.KeyPair kp2 = HASA.genKey();
        assertThrows(Exception.class, () -> HASA.decrypt(ct, kp2));
    }

    @Test
    void decrypt_fails_tamperedCiphertext() throws Exception {
        byte[] ct = HASA.encrypt(msg, kp.Q);
        ct[60] ^= 0x01; // 마지막 바이트 1비트 변조
        assertThrows(Exception.class, () -> HASA.decrypt(ct, kp));
    }

    @Test
    void decrypt_fails_tamperedNonce() throws Exception {
        byte[] ct = HASA.encrypt(msg, kp.Q);
        ct[33] ^= 0xFF; // nonce 첫 바이트 변조
        assertThrows(Exception.class, () -> HASA.decrypt(ct, kp));
    }

    @Test
    void decrypt_fails_tooShort() {
        byte[] bad = new byte[60]; // 61바이트 미만
        assertThrows(IllegalArgumentException.class, () -> HASA.decrypt(bad, kp));
    }

    // ── 잘못된 공개키 입력 거부 ──────────────────────────────────

    @Test
    void encrypt_rejects_nullQ() {
        assertThrows(IllegalArgumentException.class, () -> HASA.encrypt(msg, null));
    }

    @Test
    void encrypt_rejects_infinityQ() {
        ECPoint inf = HASA.domain.getCurve().getInfinity();
        assertThrows(IllegalArgumentException.class, () -> HASA.encrypt(msg, inf));
    }

    // ── PEM 코덱 라운드트립 ──────────────────────────────────────

    @Test
    void pem_roundTrip() throws Exception {
        byte[] ct    = HASA.encrypt(msg, kp.Q);
        String pem   = HASAPemCodec.encodeCiphertext(ct);
        byte[] ct2   = HASAPemCodec.decodeCiphertext(pem);
        byte[] plain = HASA.decrypt(ct2, kp);
        assertArrayEquals(msg, plain);
    }

    @Test
    void pem_hasCorrectHeaders() throws Exception {
        byte[] ct  = HASA.encrypt(msg, kp.Q);
        String pem = HASAPemCodec.encodeCiphertext(ct);
        assertTrue(pem.startsWith("-----BEGIN HASA CIPHERTEXT-----"));
        assertTrue(pem.contains("-----END HASA CIPHERTEXT-----"));
    }

    @Test
    void pem_rejects_tooShort() {
        String pem = "-----BEGIN HASA CIPHERTEXT-----\nAQI=\n-----END HASA CIPHERTEXT-----\n";
        assertThrows(IllegalArgumentException.class, () -> HASAPemCodec.decodeCiphertext(pem));
    }

    // ── 서명과 독립성 ────────────────────────────────────────────

    @Test
    void signAndEncrypt_independent() throws Exception {
        // 같은 키페어로 서명과 암호화 모두 가능해야 함
        HASA.Signature sig = HASA.sign(msg, kp);
        assertTrue(HASA.verify(msg, sig.R, sig.s, kp.Q));

        byte[] ct    = HASA.encrypt(msg, kp.Q);
        byte[] plain = HASA.decrypt(ct, kp);
        assertArrayEquals(msg, plain);
    }
}
