package com.hasa.crypto;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.Scanner;

public class Main {

    private static final String BEGIN_PRIV = "-----BEGIN HASA PRIVATE KEY-----\n";
    private static final String END_PRIV   = "-----END HASA PRIVATE KEY-----\n";

    private static final Scanner sc = new Scanner(System.in, StandardCharsets.UTF_8);
    private static final LinkedList<String> pushbackBuf = new LinkedList<>();

    static String readLine() {
        if (!pushbackBuf.isEmpty()) return pushbackBuf.poll();
        return sc.nextLine();
    }

    static void pushback(String line) {
        pushbackBuf.addFirst(line);
    }

    public static void main(String[] args) {
        printBanner();
        while (true) {
            printMenu();
            System.out.print("> ");
            String line = readLine().trim().replace("﻿", "");
            if (line.isEmpty()) continue;

            switch (line) {
                case "1": runGenkey();   break;
                case "2": runSign();     break;
                case "3": runVerify();   break;
                case "4": runSignfile(); break;
                case "0": case "q": case "quit": case "exit":
                    System.out.println("종료합니다.");
                    return;
                default:
                    System.out.println("알 수 없는 입력: " + line);
            }
            System.out.println();
        }
    }

    static void printBanner() {
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║   HASA CLI - secp256k1 서명 도구     ║");
        System.out.println("╚══════════════════════════════════════╝");
        System.out.println();
    }

    static void printMenu() {
        System.out.println("─────────────────────────────────────");
        System.out.println("  1. 키페어 생성");
        System.out.println("  2. 메시지 서명");
        System.out.println("  3. 서명 검증");
        System.out.println("  4. 파일 서명");
        System.out.println("  0. 종료");
        System.out.println("─────────────────────────────────────");
    }

    // ── 1. 키페어 생성 ──────────────────────────────────────────
    static void runGenkey() {
        try {
            System.out.print("저장할 이름 (Enter = 화면 출력만): ");
            String name = readLine().trim();

            HASA.KeyPair kp = HASA.genKey();
            String pubPem   = HASAPemCodec.encodePublicKey(kp.Q);
            String privPem  = encodePrivateKey(kp.privateKey());

            if (!name.isEmpty()) {
                Files.writeString(Path.of(name + ".pub"),  pubPem,  StandardCharsets.UTF_8);
                Files.writeString(Path.of(name + ".priv"), privPem, StandardCharsets.UTF_8);
                System.out.println("[저장] " + name + ".pub / " + name + ".priv");
            }
            System.out.println("[Public Key]");
            System.out.print(pubPem);
            System.out.println("[Private Key]");
            System.out.print(privPem);
        } catch (Exception e) {
            System.out.println("[오류] " + e.getMessage());
        }
    }

    // ── 2. 메시지 서명 ──────────────────────────────────────────
    static void runSign() {
        try {
            String privPem = promptPem("비밀키 (파일 경로 또는 PEM 직접 입력): ", "HASA PRIVATE KEY");

            System.out.print("서명할 메시지: ");
            String message = readLine();

            System.out.print("서명 저장 경로 (Enter = 화면 출력만): ");
            String outPath = readLine().trim();

            BigInteger d   = decodePrivateKey(privPem);
            HASA.KeyPair kp = new HASA.KeyPair(d, HASA.G.multiply(d).normalize());
            HASA.Signature sig = HASA.sign(message.getBytes(StandardCharsets.UTF_8), kp);
            String sigPem      = HASAPemCodec.encodeSignature(sig);

            if (!outPath.isEmpty()) {
                Files.writeString(Path.of(outPath), sigPem, StandardCharsets.UTF_8);
                System.out.println("[저장] " + Path.of(outPath).toAbsolutePath());
            }
            System.out.print(sigPem);
        } catch (Exception e) {
            System.out.println("[오류] " + e.getMessage());
        }
    }

    // ── 3. 서명 검증 ────────────────────────────────────────────
    static void runVerify() {
        try {
            String pubPem = promptPem("공개키 (파일 경로 또는 PEM 직접 입력): ", "HASA PUBLIC KEY");
            String sigPem = promptPem("서명 (파일 경로 또는 PEM 직접 입력): ",   "HASA SIGNATURE");

            System.out.print("검증 방식 - 메시지(m) / 파일(f): ");
            String mode = readLine().trim().toLowerCase();

            byte[] msg;
            if (mode.equals("f")) {
                System.out.print("파일 경로: ");
                String filePath = readLine().trim();
                msg = Files.readAllBytes(Path.of(filePath));
                System.out.println("[대상] 파일: " + filePath + " (" + msg.length + " bytes)");
            } else {
                System.out.print("메시지: ");
                String message = readLine();
                msg = message.getBytes(StandardCharsets.UTF_8);
                System.out.println("[대상] 메시지: " + message);
            }

            ECPoint Q          = HASAPemCodec.decodePublicKey(pubPem);
            HASA.Signature sig = HASAPemCodec.decodeSignature(sigPem);
            boolean ok         = HASA.verify(msg, sig.R, sig.s, Q);

            System.out.println("[결과] " + (ok ? "✓ 검증 성공 (OK)" : "✗ 검증 실패 (FAIL)"));
        } catch (Exception e) {
            System.out.println("[오류] " + e.getMessage());
        }
    }

    // ── 4. 파일 서명 ────────────────────────────────────────────
    static void runSignfile() {
        try {
            String privPem = promptPem("비밀키 (파일 경로 또는 PEM 직접 입력): ", "HASA PRIVATE KEY");

            System.out.print("서명할 파일 경로: ");
            String filePath = readLine().trim();

            System.out.print("서명 저장 경로 (Enter = <파일>.sig): ");
            String outPath = readLine().trim();
            if (outPath.isEmpty()) outPath = filePath + ".sig";

            BigInteger d    = decodePrivateKey(privPem);
            HASA.KeyPair kp = new HASA.KeyPair(d, HASA.G.multiply(d).normalize());
            byte[] content  = Files.readAllBytes(Path.of(filePath));
            HASA.Signature sig = HASA.sign(content, kp);
            String sigPem      = HASAPemCodec.encodeSignature(sig);

            Files.writeString(Path.of(outPath), sigPem, StandardCharsets.UTF_8);

            System.out.println("[파일] " + Path.of(filePath).toAbsolutePath());
            System.out.println("[크기] " + content.length + " bytes");
            System.out.println("[저장] " + Path.of(outPath).toAbsolutePath());
            System.out.print(sigPem);
        } catch (Exception e) {
            System.out.println("[오류] " + e.getMessage());
        }
    }

    // ── 헬퍼 ────────────────────────────────────────────────────

    /**
     * 파일 경로 또는 PEM 인라인 입력을 모두 받는다.
     * "-----BEGIN ..." 으로 시작하면 "-----END ..." 까지 멀티라인으로 읽고,
     * 그 외에는 파일 경로로 처리한다.
     */
    static String promptPem(String prompt, String pemType) throws Exception {
        System.out.print(prompt);
        String first = readLine().trim();

        if (first.startsWith("-----BEGIN")) {
            StringBuilder sb = new StringBuilder(first).append('\n');
            String endMarker = "-----END " + pemType + "-----";
            while (sc.hasNextLine()) {
                String l = readLine();
                sb.append(l).append('\n');
                if (l.trim().startsWith("-----END")) {
                    // 붙여넣기 시 END 뒤 빈 줄 소비, 내용 있으면 pushback
                    if (sc.hasNextLine()) {
                        String next = readLine();
                        if (!next.trim().isEmpty()) pushback(next);
                    }
                    break;
                }
            }
            return sb.toString();
        }

        // 파일 경로
        return readPemFile(first);
    }

    static String readPemFile(String path) throws Exception {
        byte[] bytes = Files.readAllBytes(Path.of(path));
        if (bytes.length >= 2 && bytes[0] == (byte) 0xFF && bytes[1] == (byte) 0xFE)
            return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_16LE);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static String encodePrivateKey(BigInteger d) {
        byte[] raw = BigIntegers.asUnsignedByteArray(32, d);
        String b64 = Base64.toBase64String(raw);
        StringBuilder sb = new StringBuilder(BEGIN_PRIV);
        for (int i = 0; i < b64.length(); i += 64)
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        sb.append(END_PRIV);
        return sb.toString();
    }

    static BigInteger decodePrivateKey(String pem) {
        String b64 = pem.replace(BEGIN_PRIV, "").replace(END_PRIV, "").replaceAll("\\s+", "");
        return new BigInteger(1, Base64.decode(b64));
    }
}
