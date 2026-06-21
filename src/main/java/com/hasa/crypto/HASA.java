package com.hasa.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.security.*;
import java.math.BigInteger;

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

    public static byte[] tagHash(String tag, byte[]... inputs) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(tag.getBytes());
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
        public BigInteger d;
        public ECPoint Q;
        
        public KeyPair(BigInteger d, ECPoint Q) { this.d = d; this.Q = Q; }
    }

    public static KeyPair genKey() {
        BigInteger d = new BigInteger(n.bitLength(), random).mod(n);
        ECPoint Q = G.multiply(d).normalize();
        return new KeyPair(d, Q);
    }

    // ===== NONCE (deterministic-style) =====
    public static BigInteger nonce(BigInteger d, byte[] msg) throws Exception {
        byte[] h = tagHash("NONCE-V1", enc(d), msg);
        return new BigInteger(1, h).mod(n);
    }

    // ===== CHALLENGE =====
    public static BigInteger challenge(ECPoint R, ECPoint Q, byte[] msg) throws Exception {
        byte[] e = tagHash("CHALLENGE-V1", enc(R), enc(Q), hash(msg));
        return new BigInteger(1, e).mod(n);
    }

    // ===== SINGLE SIGN =====
    public static class Signature {
        public ECPoint R;
        public BigInteger s;
        
        public Signature() {}
        public Signature(ECPoint R, BigInteger s) { this.R = R; this.s = s; }
    }

    public static Signature sign(byte[] msg, KeyPair kp) throws Exception {
        BigInteger k = nonce(kp.d, msg);
        ECPoint R = G.multiply(k).normalize();

        BigInteger e = challenge(R, kp.Q, msg);
        BigInteger s = k.add(e.multiply(kp.d)).mod(n);

        return new Signature(R, s);
    }

    // ===== VERIFY =====
    public static boolean verify(byte[] msg, ECPoint R, BigInteger s, ECPoint Q) throws Exception {
        BigInteger e = challenge(R, Q, msg);

        ECPoint left = G.multiply(s).normalize();
        ECPoint right = R.add(Q.multiply(e)).normalize();

        return left.equals(right);
    }
}