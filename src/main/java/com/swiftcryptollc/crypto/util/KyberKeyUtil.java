package com.swiftcryptollc.crypto.util;

import com.swiftcryptollc.crypto.provider.KyberKeySize;
import com.swiftcryptollc.crypto.interfaces.KyberPublicKey;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;
import com.swiftcryptollc.crypto.spec.KyberPublicKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public final class KyberKeyUtil {

    /**
     * Returns whether the key is valid or not.
     * <P>
     * Note that this method is only apply to KyberPublicKey at present.
     *
     * @param key the key object, cannot be null
     *
     * @throws NullPointerException if {@code key} is null
     * @throws InvalidKeyException if {@code key} is invalid
     */
    public static final void validate(Key key)
            throws InvalidKeyException {
        if (key == null) {
            throw new NullPointerException(
                    "The key to be validated cannot be null");
        }

        if (key instanceof KyberPublicKey) {
            validateKyberPublicKey((KyberPublicKey) key);
        }
    }

    /**
     * Returns whether the key spec is valid or not.
     * <P>
     * Note that this method is only apply to KyberPublicKeySpec at present.
     *
     * @param keySpec the key spec object, cannot be null
     *
     * @throws NullPointerException if {@code keySpec} is null
     * @throws InvalidKeyException if {@code keySpec} is invalid
     */
    public static final void validate(KeySpec keySpec)
            throws InvalidKeyException {
        if (keySpec == null) {
            throw new NullPointerException(
                    "The key spec to be validated cannot be null");
        }

        if (keySpec instanceof KyberPublicKeySpec) {
            validateKyberPublicKey((KyberPublicKeySpec) keySpec);
        }
    }

    private static void validateKyberPublicKey(KyberPublicKey publicKey)
            throws InvalidKeyException {
        int length = publicKey.getY().length;

        if ((length != 800) && (length != 1184) && (length != 1568)) {
            throw new InvalidKeyException("Unsupported Key Length " + length);
        }
    }

    private static void validateKyberPublicKey(KyberPublicKeySpec publicKeySpec)
            throws InvalidKeyException {
        int length = publicKeySpec.getY().length;

        if ((length != 800) && (length != 1184) && (length != 1568)) {
            throw new InvalidKeyException("Unsupported Key Length " + length);
        }
    }

    /**
     * Test to compare the equality of two byte arrays
     *
     * Returns 0 if they are equal
     *
     * @param x
     * @param y
     * @return
     */
    public static int constantTimeCompare(byte[] x, byte[] y) {
        if (x.length != y.length) {
            return 0;
        }

        byte v = 0;

        for (int i = 0; i < x.length; i++) {
            v = (byte) ((int) (v & 0xFF) | ((int) (x[i] & 0xFF) ^ (int) (y[i] & 0xFF)));
        }
        return Byte.compare(v, (byte) 0);
    }

    /**
     *
     * @param length
     * @return
     * @throws java.security.InvalidKeyException
     */
    public static KyberKeySize getKyberKeySizePrivateKey(int length) throws InvalidKeyException {
        if (length == KyberParams.Kyber512SKBytes) {
            return KyberKeySize.KEY_512;
        } else if (length == KyberParams.Kyber1024SKBytes) {
            return KyberKeySize.KEY_1024;
        } else if (length == KyberParams.Kyber768SKBytes) {
            return KyberKeySize.KEY_768;
        } else {
            throw new InvalidKeyException("Unsupported Key Length " + length);
        }
    }

    /**
     *
     * @param length
     * @return
     * @throws java.security.InvalidKeyException
     */
    public static KyberKeySize getKyberKeySizePublicKey(int length) throws InvalidKeyException {
        if (length == KyberParams.Kyber512PKBytes) {
            return KyberKeySize.KEY_512;
        } else if (length == KyberParams.Kyber1024PKBytes) {
            return KyberKeySize.KEY_1024;
        } else if (length == KyberParams.Kyber768PKBytes) {
            return KyberKeySize.KEY_768;
        } else {
            throw new InvalidKeyException("Unsupported Key Length " + length);
        }
    }

    /**
     * Generate a random p
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static BigInteger randomP() throws NoSuchAlgorithmException {
        SecureRandom rand = SecureRandom.getInstanceStrong();
        byte[] p = new byte[128];
        rand.nextBytes(p);
        return new BigInteger(p);
    }

    /**
     * Generate a random G
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static BigInteger randomG() throws NoSuchAlgorithmException {
        SecureRandom rand = SecureRandom.getInstanceStrong();
        byte[] g = new byte[128];
        rand.nextBytes(g);
        return new BigInteger(g);
    }

}
