package org.hyper.crypt;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.security.SecureRandom;

/**
 e      : Public Key
 d      : Private Key
 p,q    : Random Prime Numbers
 n      : p times q

 Sample Calculation of RSA encyrption method
 STEP 1 - Choose p = 3 and q = 11
 STEP 2 - Compute n = p * q = 3 * 11 = 33
 STEP 3 - Compute Ï†(n) = (p - 1) * (q - 1) = 2 * 10 = 20
 STEP 4 - Choose e such that 1 < e < Ï†(n) and e and n are coprime. Let e = 7
 STEP 5 - Compute a value for d such that (d * e) % Ï†(n) = 1. One solution is d = 3 [(3 * 7) % 20 = 1]
 STEP 6 - Public key is (e, n) => (7, 33)
 STEP 7 - Private key is (d, n) => (3, 33)
 STEP 8 - The encryption of m = 2 is c = 27 % 33 = 29
 STEP 9 - The decryption of c = 29 is m = 293 % 33 = 2


 */


public class RsaAlgorithm {
    private BigInteger n, d, e;

    private int bitlen = 1024;


    public static class RsaKey
    {
        public static final int RSA_1024 = 1024;
        public static final int RSA_2048 = 2048;
        public static final int RSA_4096 = 4096;
    }

    /**
     * Create an instance that can encrypt using someone elses public key.
     */
    public RsaAlgorithm(BigInteger calculatedRandom, BigInteger publicKey) {
        n = calculatedRandom;
        e = publicKey;
    }


    /**
     * Create an instance that can both encrypt and decrypt.
     */
    public RsaAlgorithm(int bits) {
        bitlen = bits;
        SecureRandom r = new SecureRandom();
        /**
         * Returns a random positive BigInteger instance in the range [0, pow(2, bitLength)-1]
         * which is probably prime. The probability that the returned BigInteger is prime is
         * greater than 1 - 1/2<sup>100</sup>).
         */

        /********************************STEP 1******************************/
        //RANDOM PRIME 1
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        //RANDOM PRIME 2
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        /********************************************************************/

        /*********************************STEP 2*****************************/
        //MULTIPLY 2 RANDOM PRIME
        n = p.multiply(q);
        /********************************************************************/

        /********************************STEP 3*******************************/
        //CALCULATE Ï†(n) = (p - 1) * (q - 1)
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        /**********************************************************************/

        /********************************STEP 4********************************/
        //Choose e such that 1 < e < Ï†(n) and e and n are coprime
        /**
         * Returns a BigInteger whose value is greatest common divisor of this and value.
         * If this == 0 and value == 0 then zero is returned, otherwise the result is positive.
         */
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }


        /**
         * Returns a BigInteger whose value is 1/this mod m. The modulus m must be positive.
         * The result is guaranteed to be in the interval [0, m) (0 inclusive, m exclusive).
         * If this is not relatively prime to m, then an exception is thrown.
         */
        d = e.modInverse(m);
    }

    /**
     * Encrypt the given plaintext message.
     */
    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(e, n).toString();
    }

    /**
     * Encrypt the given plaintext message.
     */
    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    /**
     * Decrypt the given ciphertext message.
     */
    public synchronized String decrypt(String message) {
        String decyrptionResult = new String((new BigInteger(message)).modPow(d, n).toByteArray());
        if(!isUTF8MisInterpreted(decyrptionResult)){
            decyrptionResult = null;
        }
        return decyrptionResult;
    }

    /**
     * Decrypt the given ciphertext message.
     */
    public synchronized BigInteger decrypt(BigInteger message) {
        return message.modPow(d, n);
    }

    /**
     * Generate a new public and private key set.
     */
    public synchronized void generateKeys() {
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }

    /**
     * Return the modulus.
     */
    public synchronized BigInteger getN() {
        return n;
    }

    /**
     * Return the public key.
     */
    public synchronized BigInteger getE() {
        return e;
    }

    public static boolean isUTF8MisInterpreted(String input) {
        return isUTF8MisInterpreted(input, "Windows-1252");
    }

    public static boolean isUTF8MisInterpreted(String input, String encoding) {

        CharsetDecoder decoder = Charset.forName("UTF-8").newDecoder();
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