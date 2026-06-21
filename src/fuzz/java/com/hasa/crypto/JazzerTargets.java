package com.hasa.crypto;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Jazzer coverage-guided 퍼징 타겟.
 *
 * 실행:
 *   mvn test -Pfuzz
 *
 * 고강도 실행 (오래 돌릴 때):
 *   mvn test -Pfuzz -Djazzer.runs=1000000
 *
 * 크래시 재현:
 *   mvn test -Pfuzz -Djazzer.reproducingArgs="<crash_input_hex>"
 *
 * Jazzer는 JaCoCo 커버리지를 추적하며 커버리지를 높이는 방향으로 입력을 변이시킨다.
 * 일반 random fuzzing보다 훨씬 깊은 코드 경로를 탐색한다.
 */
class JazzerTargets {

    // ── T1: sign→verify 전체 파이프라인 ─────────────────────────
    // 목표: 임의 메시지로 서명/검증 라운드트립 크래시 없음을 보장
    @FuzzTest
    void fuzz_signVerify(FuzzedDataProvider data) throws Exception {
        byte[] msg = data.consumeRemainingAsBytes();
        HASA.KeyPair kp = HASA.genKey();
        HASA.Signature sig = HASA.sign(msg, kp);
        if (!HASA.verify(msg, sig.R, sig.s, kp.Q)) {
            throw new AssertionError("sign/verify 실패: msg.len=" + msg.length);
        }
    }

    // ── T2: 서명 PEM 디코딩 ──────────────────────────────────────
    // 목표: 임의 Base64 페이로드 → 명확한 예외만, NPE/AIOBE 없음
    @FuzzTest
    void fuzz_decodeSignaturePem(FuzzedDataProvider data) throws Exception {
        String payload = data.consumeRemainingAsString();
        String pem = "-----BEGIN HASA SIGNATURE-----\n"
                   + payload
                   + "\n-----END HASA SIGNATURE-----\n";
        try {
            HASAPemCodec.decodeSignature(pem);
        } catch (IllegalArgumentException | IllegalStateException
               | org.bouncycastle.crypto.DataLengthException e) {
            // 예상 예외 — 정상
        }
    }

    // ── T3: 공개키 PEM 디코딩 ────────────────────────────────────
    @FuzzTest
    void fuzz_decodePublicKeyPem(FuzzedDataProvider data) throws Exception {
        String payload = data.consumeRemainingAsString();
        String pem = "-----BEGIN HASA PUBLIC KEY-----\n"
                   + payload
                   + "\n-----END HASA PUBLIC KEY-----\n";
        try {
            HASAPemCodec.decodePublicKey(pem);
        } catch (IllegalArgumentException | IllegalStateException
               | org.bouncycastle.crypto.DataLengthException e) {
            // 예상 예외 — 정상
        }
    }

    // ── T4: verify에 임의 s값 공급 ───────────────────────────────
    // 목표: 예외 없이 true/false 반환
    @FuzzTest
    void fuzz_verifyArbitraryInputs(FuzzedDataProvider data) throws Exception {
        byte[] msg    = data.consumeBytes(64);
        byte[] sBytes = data.consumeBytes(32);
        byte[] kBytes = data.consumeBytes(32);

        // R은 유효한 점으로 고정 (arbitrary k)
        BigInteger kInt = new BigInteger(1, kBytes.length == 0 ? new byte[]{1} : kBytes);
        kInt = kInt.mod(HASA.n);
        if (kInt.equals(BigInteger.ZERO)) kInt = BigInteger.ONE;
        org.bouncycastle.math.ec.ECPoint R = HASA.G.multiply(kInt).normalize();

        HASA.KeyPair kp = HASA.genKey();
        BigInteger s = new BigInteger(1, sBytes.length == 0 ? new byte[]{1} : sBytes);

        // 예외 없이 반환해야 함
        HASA.verify(msg, R, s, kp.Q);
    }

    // ── T5: tagHash 임의 입력 ────────────────────────────────────
    // 목표: 항상 32바이트 반환
    @FuzzTest
    void fuzz_tagHash(FuzzedDataProvider data) throws Exception {
        String tag   = data.consumeString(64);
        byte[] input = data.consumeRemainingAsBytes();
        byte[] result = HASA.tagHash(tag, input);
        if (result.length != 32) {
            throw new AssertionError("tagHash 결과 != 32바이트: " + result.length);
        }
    }
}
