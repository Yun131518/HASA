package com.hasa.crypto;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

import java.util.Arrays;

/**
 * libsecp256k1 JNA 바인딩.
 *
 * 왜 필요한가:
 *   Java BigInteger.multiply() 는 값에 따라 실행 경로가 달라지는 비상수시간 코드다.
 *   libsecp256k1은 C 레벨에서 CMOV 명령을 사용해 진정한 상수시간을 보장한다.
 *   이 클래스가 로드되면 sign() 이 자동으로 상수시간 경로를 사용한다.
 *
 * 활성화 방법 (Windows):
 *   1. MSYS2 설치 후 MinGW64 셸에서:
 *        pacman -S mingw-w64-x86_64-secp256k1
 *      → C:\msys64\mingw64\bin\libsecp256k1-0.dll 생성됨
 *   2. DLL을 java.library.path 에 위치 (예: JAR 와 같은 폴더) 하고
 *      파일명을 secp256k1.dll 로 변경
 *   3. 재실행하면 HASA.NativeSecp256k1.AVAILABLE == true 로 변경됨
 *
 * 활성화 방법 (Linux):
 *   apt install libsecp256k1-dev  (또는 pacman -S secp256k1)
 *   → /usr/lib/libsecp256k1.so 가 자동으로 발견됨
 */
public final class NativeSecp256k1 {

    /** true 이면 libsecp256k1 로드 완료 → sign()이 상수시간 경로 사용 */
    public static final boolean AVAILABLE;

    private static final Secp256k1Lib LIB;
    private static final Pointer       CTX;

    // ── JNA 인터페이스 ──────────────────────────────────────────
    private interface Secp256k1Lib extends Library {
        int CONTEXT_SIGN  = 0x0201;
        int EC_COMPRESSED = 0x0102;

        Pointer secp256k1_context_create(int flags);
        void    secp256k1_context_destroy(Pointer ctx);

        // G * seckey → 64바이트 내부 공개키 표현 (상수시간)
        int secp256k1_ec_pubkey_create(Pointer ctx, byte[] pubkey64, byte[] seckey32);

        // pubkey64 → 압축/비압축 바이트열 직렬화
        int secp256k1_ec_pubkey_serialize(Pointer ctx, byte[] output, IntByReference outputLen,
                                          byte[] pubkey64, int flags);

        // seckey32 = seckey32 * tweak32 mod n  (상수시간)
        int secp256k1_ec_seckey_tweak_mul(Pointer ctx, byte[] seckey32, byte[] tweak32);

        // seckey32 = seckey32 + tweak32 mod n  (상수시간)
        int secp256k1_ec_seckey_tweak_add(Pointer ctx, byte[] seckey32, byte[] tweak32);

        // 키 유효성 검사
        int secp256k1_ec_seckey_verify(Pointer ctx, byte[] seckey32);
    }

    // ── 초기화 ──────────────────────────────────────────────────
    static {
        Secp256k1Lib lib = null;
        Pointer ctx = null;
        boolean avail = false;
        try {
            lib = Native.load("secp256k1", Secp256k1Lib.class);
            ctx = lib.secp256k1_context_create(Secp256k1Lib.CONTEXT_SIGN);
            avail = (ctx != null && !Pointer.NULL.equals(ctx));
            if (avail) {
                System.err.println("[HASA] libsecp256k1 로드 완료 — 상수시간 서명 활성화");
            }
        } catch (UnsatisfiedLinkError | Exception ignored) {
            // DLL/SO 없음 → Java 폴백 경로 사용 (AVAILABLE == false)
        }
        LIB       = lib;
        CTX       = ctx;
        AVAILABLE = avail;
    }

    private NativeSecp256k1() {}

    // ── 공개키 생성: G * seckey  (상수시간) ────────────────────
    static synchronized byte[] pubkeyCreate(byte[] seckey32) throws Exception {
        byte[] buf = new byte[64]; // 내부 표현 (opaque)
        if (LIB.secp256k1_ec_pubkey_create(CTX, buf, seckey32) != 1)
            throw new IllegalArgumentException("secp256k1: 유효하지 않은 비밀키");

        byte[] compressed = new byte[33];
        IntByReference len = new IntByReference(33);
        if (LIB.secp256k1_ec_pubkey_serialize(CTX, compressed, len, buf, Secp256k1Lib.EC_COMPRESSED) != 1)
            throw new IllegalStateException("secp256k1: 공개키 직렬화 실패");

        return compressed;
    }

    // ── a * b mod n  (상수시간) ──────────────────────────────────
    static synchronized byte[] scalarMul(byte[] a32, byte[] b32) throws Exception {
        byte[] result = a32.clone();
        try {
            // tweak_mul: result = result * b32 mod n
            if (LIB.secp256k1_ec_seckey_tweak_mul(CTX, result, b32) != 1)
                throw new ArithmeticException("secp256k1: 스칼라 곱 실패 (0이 되는 경우)");
            return result;
        } catch (Exception ex) {
            Arrays.fill(result, (byte) 0);
            throw ex;
        }
    }

    // ── a + b mod n  (상수시간) ──────────────────────────────────
    static synchronized byte[] scalarAdd(byte[] a32, byte[] b32) throws Exception {
        byte[] result = a32.clone();
        try {
            // tweak_add: result = result + b32 mod n
            if (LIB.secp256k1_ec_seckey_tweak_add(CTX, result, b32) != 1)
                throw new ArithmeticException("secp256k1: 스칼라 합 실패");
            return result;
        } catch (Exception ex) {
            Arrays.fill(result, (byte) 0);
            throw ex;
        }
    }
}
