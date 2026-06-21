package com.hasa.crypto;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public class HASA {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ===== CURVE =====
    // CustomNamedCurves 사용 이유:
    //   ECNamedCurveTable 의 제네릭 구현 대신, secp256k1 전용 GLV(Gallant-Lambert-Vanstone)
    //   엔도모피즘을 활성화한다. GLV는 256비트 스칼라를 두 개의 ~128비트 스칼라로 분해하여
    //   EC 포인트 곱셈 시 타이밍 노출을 256비트 → ~128비트로 절반 감소시킨다.
    private static final X9ECParameters  CURVE_X9 = CustomNamedCurves.getByName("secp256k1");
    public  static final ECDomainParameters domain  = new ECDomainParameters(
            CURVE_X9.getCurve(), CURVE_X9.getG(), CURVE_X9.getN(), CURVE_X9.getH());
    public  static final ECPoint    G      = domain.getG();
    public  static final BigInteger n      = domain.getN();
    private static final SecureRandom random = new SecureRandom();

    // ===== HASH =====
    // 주의: 가변 길이 복수 입력에 사용하면 연결 모호성이 생긴다.
    // 내부 호출은 반드시 고정 크기 입력(enc 결과 등)만 사용할 것.
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

    // ===== NONCE =====
    // attempt: sign()의 외부 재시도 카운터 (e=0 또는 s=0인 경우 사용)
    // counter:  k >= n 인 극히 드문 경우의 내부 rejection 카운터
    // 두 카운터 모두 int → 4바이트 big-endian으로 인코딩하여 byte 오버플로 방지
    public static BigInteger nonce(BigInteger d, byte[] msg) throws Exception {
        return nonceInternal(d, msg, 0);
    }

    static BigInteger nonceInternal(BigInteger d, byte[] msg, int attempt) throws Exception {
        byte[] attemptBytes = intToBytes(attempt);
        for (int counter = 0; ; counter++) {
            byte[] h = tagHash("NONCE-V1", enc(d), msg, attemptBytes, intToBytes(counter));
            BigInteger k = new BigInteger(1, h);
            if (k.compareTo(BigInteger.ONE) >= 0 && k.compareTo(n) < 0) {
                return k;
            }
        }
    }

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v};
    }

    // ===== CHALLENGE =====
    // e=0이면 sign()에서 s = k가 되어 논스가 직접 노출된다.
    // 발생 확률 ~2^-256이지만 0은 1로 대체한다.
    // 서명자와 검증자 모두 동일한 규칙을 적용하므로 일관성이 유지된다.
    public static BigInteger challenge(ECPoint R, ECPoint Q, byte[] msg) throws Exception {
        byte[] e = tagHash("CHALLENGE-V1", enc(R), enc(Q), hash(msg));
        BigInteger c = new BigInteger(1, e).mod(n);
        return c.equals(BigInteger.ZERO) ? BigInteger.ONE : c;
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
        return NativeSecp256k1.AVAILABLE ? signNative(msg, kp) : signJava(msg, kp);
    }

    // ── 상수시간 경로: libsecp256k1 (NativeSecp256k1.AVAILABLE == true 일 때) ──
    // G*k, e*d mod n, k + e*d mod n 전부 C 레벨 CMOV로 상수시간 보장
    private static Signature signNative(byte[] msg, KeyPair kp) throws Exception {
        for (int attempt = 0; ; attempt++) {
            BigInteger k   = nonceInternal(kp.privateKey(), msg, attempt);
            byte[]     kb  = enc(k);              // 32바이트 big-endian
            byte[]     db  = enc(kp.privateKey());// 비밀키 바이트 (사용 후 제로화)
            try {
                // 1. R = G * k (상수시간)
                byte[]  Rb = NativeSecp256k1.pubkeyCreate(kb);
                ECPoint R  = domain.getCurve().decodePoint(Rb).normalize();

                BigInteger e = challenge(R, kp.Q, msg);
                if (e.equals(BigInteger.ZERO)) continue;

                byte[] eb = enc(e);

                // 2. ed = e * d mod n (상수시간)
                byte[] ed = NativeSecp256k1.scalarMul(db, eb);
                // 3. s  = k + ed mod n (상수시간)
                byte[] sb = NativeSecp256k1.scalarAdd(ed, kb);
                Arrays.fill(ed, (byte) 0);

                BigInteger s = new BigInteger(1, sb);
                if (s.equals(BigInteger.ZERO)) continue;

                return new Signature(R, s);
            } finally {
                Arrays.fill(db, (byte) 0); // 비밀키 바이트 즉시 제로화
            }
        }
    }

    // ── Java 폴백: 스칼라 블라인딩으로 타이밍 완화 (libsecp256k1 없을 때) ──
    // BigInteger.multiply() 는 비상수시간이지만 r*n 블라인딩으로 상관관계 분석을 어렵게 함
    private static Signature signJava(byte[] msg, KeyPair kp) throws Exception {
        for (int attempt = 0; ; attempt++) {
            BigInteger k = nonceInternal(kp.privateKey(), msg, attempt);
            ECPoint R    = G.multiply(k).normalize();

            BigInteger e = challenge(R, kp.Q, msg);
            if (e.equals(BigInteger.ZERO)) continue;

            // 스칼라 블라인딩: d_blind = d + r*n → e*d_blind mod n = e*d mod n
            BigInteger r       = new BigInteger(64, random);
            BigInteger d_blind = kp.privateKey().add(r.multiply(n));
            BigInteger s       = k.add(e.multiply(d_blind)).mod(n);

            if (s.equals(BigInteger.ZERO)) continue;

            return new Signature(R, s);
        }
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
