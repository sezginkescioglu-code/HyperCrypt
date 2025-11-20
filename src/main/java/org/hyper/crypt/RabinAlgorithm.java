package org.hyper.crypt;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.security.SecureRandom;
import java.util.Random;

public class RabinAlgorithm {
    private static final Random r = new SecureRandom();
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static BigInteger p;
    private static BigInteger q;
    private static BigInteger N;


    public static class RabinKey
    {
        public static final int RABIN_1024 = 1024;
        public static final int RABIN_2048 = 2048;
        public static final int RABIN_4096 = 4096;
    }

    /**
     * Generate a blum public and private key (more efficient decryption) with a specified number of bits
     * @param bitLength Number of bits in public key
     *
     */
    public static void genKey(int bitLength) {
        p = blumPrime(bitLength / 2);
        q = blumPrime(bitLength / 2);
        N = p.multiply(q);
    }

    /**
     * Encrypt a value with the public key
     * @return c, the encrypted value
     */
    public static String encrypt(String message) {
        BigInteger binaryMode = new BigInteger(message.getBytes(StandardCharsets.US_ASCII));
        return binaryMode.modPow(TWO, N).toString();
    }

    /**
     * Decrypt a value with the private key (assumes blum key for fast decryption)
     * @param c encrypted number
     * @return array of the 4 decryption possibilities
     */
    public static String decrypt(String c) {

        String decyrptedMessage = null;
        BigInteger binaryMode = new BigInteger(c);

        BigInteger N = p.multiply(q);
        BigInteger m_p1 = binaryMode.modPow(p.add(BigInteger.ONE).divide(FOUR), p);
        BigInteger m_p2 = p.subtract(m_p1);
        BigInteger m_q1 = binaryMode.modPow(q.add(BigInteger.ONE).divide(FOUR), q);
        BigInteger m_q2 = q.subtract(m_q1);

        BigInteger[] ext = ext_gcd(p, q);
        BigInteger y_p = ext[1];
        BigInteger y_q = ext[2];

        //y_p*p*m_q + y_q*q*m_p (mod n)
        BigInteger d1 = y_p.multiply(p).multiply(m_q1).add(y_q.multiply(q).multiply(m_p1)).mod(N);
        BigInteger d2 = y_p.multiply(p).multiply(m_q2).add(y_q.multiply(q).multiply(m_p1)).mod(N);
        BigInteger d3 = y_p.multiply(p).multiply(m_q1).add(y_q.multiply(q).multiply(m_p2)).mod(N);
        BigInteger d4 = y_p.multiply(p).multiply(m_q2).add(y_q.multiply(q).multiply(m_p2)).mod(N);

        BigInteger[] decyrptionResultArray = new BigInteger[] {
                d1,
                d2,
                d3,
                d4
        };

        for (BigInteger decyrptedMessagePart: decyrptionResultArray) {
            String possible = new String(decyrptedMessagePart.toByteArray(), StandardCharsets.US_ASCII);
            if (isUTF8MisInterpreted(possible)) {
                decyrptedMessage = possible;
            }
        }

        return decyrptedMessage;
    }


    public static BigInteger[] ext_gcd(BigInteger a, BigInteger b) {
        BigInteger s = BigInteger.ZERO;
        BigInteger old_s = BigInteger.ONE;
        BigInteger t = BigInteger.ONE;
        BigInteger old_t = BigInteger.ZERO;
        BigInteger r = b;
        BigInteger old_r = a;
        while (!r.equals(BigInteger.ZERO)) {
            BigInteger q = old_r.divide(r);
            BigInteger tr = r;
            r = old_r.subtract(q.multiply(r));
            old_r = tr;

            BigInteger ts = s;
            s = old_s.subtract(q.multiply(s));
            old_s = ts;

            BigInteger tt = t;
            t = old_t.subtract(q.multiply(t));
            old_t = tt;
        }
        //gcd, x,y
        //x,y such that ax+by=gcd(a,b)
        return new BigInteger[] {
                old_r,
                old_s,
                old_t
        };
    }

    /**
     * Generate a random blum prime ( a prime such that pâ‰¡3 (mod 4) )
     * @param bitLength number of bits in the prime
     * @return a random blum prime
     */
    public static BigInteger blumPrime(int bitLength) {
        BigInteger p;
        do {
            p = BigInteger.probablePrime(bitLength, r);
        }
        while (!p.mod(FOUR).equals(THREE));
        return p;
    }

    public static boolean isUTF8MisInterpreted(String input) {
        return isUTF8MisInterpreted(input, "Windows-1252");
    }

    public static boolean isUTF8MisInterpreted(String input, String encoding) {

        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
        CharsetEncoder encoder = Charset.forName(encoding).newEncoder();
        ByteBuffer tmp;
        try {
            tmp = encoder.encode(CharBuffer.wrap(input));
        } catch (CharacterCodingException e) {
            return false;
        }

        try {
            decoder.decode(tmp);
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }
}