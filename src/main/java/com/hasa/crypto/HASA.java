package com.hasa.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class HASA {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ===== CURVE =====
    public static final ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
    public static final ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
    public static final ECPoint G = domain.getG();
    public static final BigInteger n = domain.getN();
    private static final SecureRandom random = new SecureRandom();

    // ===== HASH =====
    public static byte[] hash(byte[]... inputs) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] i : inputs) md.update(i);
        return md.digest();
    }

    // BIP340 스타일 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || inputs...)
    // 태그별 도메인을 완전히 분리하여 교차 태그 충돌을 방지한다.
    public static byte[] tagHash(String tag, byte[]... inputs) throws Exception {
        byte[] tagDigest = hash(tag.getBytes(StandardCharsets.UTF_8));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(tagDigest);
        md.update(tagDigest);
        for (byte[] i : inputs) md.update(i);
        return md.digest();
    }

    // ===== ENCODING =====
    public static byte[] enc(ECPoint p) {
        return p.normalize().getEncoded(true);
    }

    public static byte[] enc(BigInteger x) {
        return BigIntegers.asUnsignedByteArray(32, x);
    }

    // ===== KEYPAIR =====
    public static class KeyPair {
        private final BigInteger d;
        public final ECPoint Q;

        public KeyPair(BigInteger d, ECPoint Q) {
            this.d = d;
            this.Q = Q;
        }

        // 같은 패키지 내 서명 연산에만 접근 허용
        BigInteger privateKey() { return d; }
    }

    // rejection sampling으로 편향 없는 키 생성
    public static KeyPair genKey() {
        BigInteger d;
        do {
            d = new BigInteger(256, random);
        } while (d.compareTo(BigInteger.ONE) < 0 || d.compareTo(n) >= 0);
        ECPoint Q = G.multiply(d).normalize();
        return new KeyPair(d, Q);
    }

    // ===== NONCE (결정론적 + rejection sampling) =====
    // counter를 포함해 k >= n 인 극히 드문 경우(확률 ~2^-128)에도 안전하게 재시도한다.
    public static BigInteger nonce(BigInteger d, byte[] msg) throws Exception {
        for (int counter = 0; ; counter++) {
            byte[] h = tagHash("NONCE-V1", enc(d), msg, new byte[]{(byte) counter});
            BigInteger k = new BigInteger(1, h);
            if (k.compareTo(BigInteger.ONE) >= 0 && k.compareTo(n) < 0) {
                return k;
            }
        }
    }

    // ===== CHALLENGE =====
    public static BigInteger challenge(ECPoint R, ECPoint Q, byte[] msg) throws Exception {
        byte[] e = tagHash("CHALLENGE-V1", enc(R), enc(Q), hash(msg));
        return new BigInteger(1, e).mod(n);
    }

    // ===== SIGNATURE =====
    public static class Signature {
        public final ECPoint R;
        public final BigInteger s;

        public Signature(ECPoint R, BigInteger s) {
            this.R = R;
            this.s = s;
        }
    }

    public static Signature sign(byte[] msg, KeyPair kp) throws Exception {
        BigInteger k = nonce(kp.privateKey(), msg);
        ECPoint R = G.multiply(k).normalize();

        BigInteger e = challenge(R, kp.Q, msg);
        BigInteger s = k.add(e.multiply(kp.privateKey())).mod(n);

        return new Signature(R, s);
    }

    // ===== VERIFY =====
    public static boolean verify(byte[] msg, ECPoint R, BigInteger s, ECPoint Q) throws Exception {
        // 입력값 범위 검사: 잘못된 값으로 인한 위조 서명 허용 방지
        if (R == null || R.isInfinity()) return false;
        if (Q == null || Q.isInfinity()) return false;
        if (s == null || s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) return false;

        BigInteger e = challenge(R, Q, msg);

        ECPoint left  = G.multiply(s).normalize();
        ECPoint right = R.add(Q.multiply(e)).normalize();

        return left.equals(right);
    }
}
