package com.hasa.crypto;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;

public class HASAPemCodec {

    private static final String BEGIN_PUB = "-----BEGIN HASA PUBLIC KEY-----\n";
    private static final String END_PUB   = "-----END HASA PUBLIC KEY-----\n";
    private static final String BEGIN_SIG = "-----BEGIN HASA SIGNATURE-----\n";
    private static final String END_SIG   = "-----END HASA SIGNATURE-----\n";

    // 1. 공개키(Q) -> PEM 문자열 추출 (네트워크 전송/파일 저장용)
    public static String encodePublicKey(ECPoint publicKey) {
        String base64 = Base64.toBase64String(HASA.enc(publicKey));
        return BEGIN_PUB + formatLines(base64) + END_PUB;
    }

    // 2. 서명(R, s) -> PEM 문자열 추출 (네트워크 전송/파일 저장용)
    public static String encodeSignature(HASA.Signature signature) {
        byte[] rawR = HASA.enc(signature.R);
        byte[] rawS = HASA.enc(signature.s);

        byte[] combined = new byte[65];
        System.arraycopy(rawR, 0, combined, 0, 33);
        System.arraycopy(rawS, 0, combined, 33, 32);

        return BEGIN_SIG + formatLines(Base64.toBase64String(combined)) + END_SIG;
    }

    // 3. PEM 문자열 -> 공개키(Q) 복원
    public static ECPoint decodePublicKey(String pem) throws Exception {
        String base64 = pem.replace(BEGIN_PUB, "").replace(END_PUB, "").replaceAll("\\s+", "");
        byte[] raw = Base64.decode(base64);
        if (raw.length != 33) {
            throw new IllegalArgumentException(
                "공개키 데이터 길이 오류: " + raw.length + " 바이트 (33 바이트 필요)");
        }
        return HASA.domain.getCurve().decodePoint(raw).normalize();
    }

    // 4. PEM 문자열 -> 서명(R, s) 복원
    public static HASA.Signature decodeSignature(String pem) throws Exception {
        String base64 = pem.replace(BEGIN_SIG, "").replace(END_SIG, "").replaceAll("\\s+", "");
        byte[] combined = Base64.decode(base64);

        if (combined.length != 65) {
            throw new IllegalArgumentException(
                "서명 데이터 길이 오류: " + combined.length + " 바이트 (65 바이트 필요)");
        }

        byte[] rawR = new byte[33];
        byte[] rawS = new byte[32];
        System.arraycopy(combined, 0,  rawR, 0, 33);
        System.arraycopy(combined, 33, rawS, 0, 32);

        ECPoint r = HASA.domain.getCurve().decodePoint(rawR).normalize();
        BigInteger s = new BigInteger(1, rawS);
        return new HASA.Signature(r, s);
    }

    private static String formatLines(String base64) {
        StringBuilder sb = new StringBuilder();
        int index = 0;
        while (index < base64.length()) {
            sb.append(base64, index, Math.min(index + 64, base64.length())).append("\n");
            index += 64;
        }
        return sb.toString();
    }
}