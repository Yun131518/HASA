package com.hasa.crypto;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HASAPemCodec 단위 테스트.
 *
 * 커버 범위:
 *  - 공개키 PEM 라운드트립
 *  - 서명 PEM 라운드트립
 *  - PEM 형식 헤더/풋터 검증
 *  - 인코딩된 서명 크기 (65바이트)
 *  - 잘못된 길이 / 잘못된 포인트 거부
 */
class HASAPemCodecTest {

    private HASA.KeyPair kp;
    private byte[]       msg;
    private HASA.Signature sig;

    @BeforeEach
    void setup() throws Exception {
        kp  = HASA.genKey();
        msg = "codec test".getBytes(StandardCharsets.UTF_8);
        sig = HASA.sign(msg, kp);
    }

    // ── 공개키 ──────────────────────────────────────────────────

    @Test
    void publicKey_roundTrip() throws Exception {
        String  pem     = HASAPemCodec.encodePublicKey(kp.Q);
        ECPoint decoded = HASAPemCodec.decodePublicKey(pem);
        assertEquals(kp.Q.normalize(), decoded.normalize());
    }

    @Test
    void publicKey_hasCorrectHeaders() throws Exception {
        String pem = HASAPemCodec.encodePublicKey(kp.Q);
        assertTrue(pem.startsWith("-----BEGIN HASA PUBLIC KEY-----"));
        assertTrue(pem.contains("-----END HASA PUBLIC KEY-----"));
    }

    @Test
    void publicKey_encodedIs33Bytes() throws Exception {
        String pem = HASAPemCodec.encodePublicKey(kp.Q);
        String b64 = pem.replace("-----BEGIN HASA PUBLIC KEY-----\n", "")
                        .replace("-----END HASA PUBLIC KEY-----\n", "")
                        .replaceAll("\\s+", "");
        assertEquals(33, Base64.decode(b64).length, "압축 공개키는 33바이트여야 함");
    }

    @Test
    void publicKey_decodedIsOnCurve() throws Exception {
        String  pem = HASAPemCodec.encodePublicKey(kp.Q);
        ECPoint q   = HASAPemCodec.decodePublicKey(pem);
        assertTrue(q.isValid(), "디코딩된 공개키가 곡선 위에 있어야 함");
        assertFalse(q.isInfinity());
    }

    @Test
    void publicKey_decodedVerifiesSignature() throws Exception {
        String  pem = HASAPemCodec.encodePublicKey(kp.Q);
        ECPoint q   = HASAPemCodec.decodePublicKey(pem);
        assertTrue(HASA.verify(msg, sig.R, sig.s, q));
    }

    // ── 서명 ────────────────────────────────────────────────────

    @Test
    void signature_roundTrip() throws Exception {
        String         pem     = HASAPemCodec.encodeSignature(sig);
        HASA.Signature decoded = HASAPemCodec.decodeSignature(pem);
        assertEquals(sig.R.normalize(), decoded.R.normalize());
        assertEquals(sig.s, decoded.s);
    }

    @Test
    void signature_hasCorrectHeaders() throws Exception {
        String pem = HASAPemCodec.encodeSignature(sig);
        assertTrue(pem.startsWith("-----BEGIN HASA SIGNATURE-----"));
        assertTrue(pem.contains("-----END HASA SIGNATURE-----"));
    }

    @Test
    void signature_encodedIs65Bytes() throws Exception {
        String pem = HASAPemCodec.encodeSignature(sig);
        String b64 = pem.replace("-----BEGIN HASA SIGNATURE-----\n", "")
                        .replace("-----END HASA SIGNATURE-----\n", "")
                        .replaceAll("\\s+", "");
        assertEquals(65, Base64.decode(b64).length, "서명은 65바이트(R:33 + s:32)여야 함");
    }

    @Test
    void signature_decodedVerifiesSuccessfully() throws Exception {
        String         pem     = HASAPemCodec.encodeSignature(sig);
        HASA.Signature decoded = HASAPemCodec.decodeSignature(pem);
        assertTrue(HASA.verify(msg, decoded.R, decoded.s, kp.Q));
    }

    // ── 잘못된 입력 거부 ─────────────────────────────────────────

    @Test
    void decodeSignature_rejects_tooShort() {
        // 3바이트 Base64 → 2바이트 decoded (65바이트가 아님)
        String bad = "-----BEGIN HASA SIGNATURE-----\nAQID\n-----END HASA SIGNATURE-----\n";
        assertThrows(Exception.class, () -> HASAPemCodec.decodeSignature(bad));
    }

    @Test
    void decodeSignature_rejects_tooLong() {
        // 66바이트짜리 Base64 (65바이트가 아님)
        byte[] longBytes = new byte[66];
        String b64 = Base64.toBase64String(longBytes);
        String pem = "-----BEGIN HASA SIGNATURE-----\n" + b64 + "\n-----END HASA SIGNATURE-----\n";
        assertThrows(Exception.class, () -> HASAPemCodec.decodeSignature(pem));
    }

    @Test
    void decodePublicKey_rejects_invalidPoint() {
        // 33바이트 0x00... 은 유효한 압축 점이 아님
        byte[] bad = new byte[33];
        String b64 = Base64.toBase64String(bad);
        String pem = "-----BEGIN HASA PUBLIC KEY-----\n" + b64 + "\n-----END HASA PUBLIC KEY-----\n";
        assertThrows(Exception.class, () -> HASAPemCodec.decodePublicKey(pem));
    }

    // ── PEM 줄 길이 ──────────────────────────────────────────────

    @Test
    void signature_pemLineWidth_atMost64Chars() throws Exception {
        String pem = HASAPemCodec.encodeSignature(sig);
        for (String line : pem.split("\n")) {
            if (line.startsWith("-----")) continue;
            assertTrue(line.length() <= 64, "PEM 줄이 64자를 초과함: " + line);
        }
    }

    @Test
    void publicKey_pemLineWidth_atMost64Chars() throws Exception {
        String pem = HASAPemCodec.encodePublicKey(kp.Q);
        for (String line : pem.split("\n")) {
            if (line.startsWith("-----")) continue;
            assertTrue(line.length() <= 64, "PEM 줄이 64자를 초과함: " + line);
        }
    }
}
