package com.swiftcryptollc.crypto.spec;

import com.swiftcryptollc.crypto.provider.KyberKeySize;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public final class KyberParameterSpec implements AlgorithmParameterSpec {

    // The prime modulus
    private BigInteger p;

    // The base generator
    private BigInteger g;

    // The size in bits of the random exponent (private value) (optional)
    private int l;

    private int keySize;
    private KyberKeySize kyberKeySize;

    /**
     * Constructs a parameter set for Kyber, using a prime modulus
     * <code>p</code>, a base generator <code>g</code>, and the size in bits,
     * <code>l</code>, of the random exponent (private value).
     *
     * @param p the prime modulus
     * @param g the base generator
     * @param l the size in bits of the random exponent (private value)
     */
    public KyberParameterSpec(BigInteger p, BigInteger g, int l) {
        this.p = p;
        this.g = g;
        this.l = l;
        try {
            setKyberKeySize(this.l);
        } catch (InvalidKeyException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }
    }

    /**
     * Set the KyberKeySize based on the key length (private and public have
     * different lengths)
     *
     * @param length
     * @return
     */
    private void setKyberKeySize(int length) throws InvalidKeyException {
        this.keySize = length;

        switch (keySize) {
            case KyberParams.Kyber512SKBytes:
            case KyberParams.Kyber512PKBytes:
                this.kyberKeySize = KyberKeySize.KEY_512;
                break;
            case KyberParams.Kyber768SKBytes:
            case KyberParams.Kyber768PKBytes:
                this.kyberKeySize = KyberKeySize.KEY_768;
                break;
            case KyberParams.Kyber1024SKBytes:
            case KyberParams.Kyber1024PKBytes:
                this.kyberKeySize = KyberKeySize.KEY_1024;
                break;
            default:
                throw new InvalidKeyException("Invalid Kyber Key Size! [" + length + "]");
        }
    }

    /**
     * Returns the prime modulus <code>p</code>.
     *
     * @return the prime modulus <code>p</code>
     */
    public BigInteger getP() {
        return this.p;
    }

    /**
     * Returns the base generator <code>g</code>.
     *
     * @return the base generator <code>g</code>
     */
    public BigInteger getG() {
        return this.g;
    }

    /**
     * Returns the size in bits, <code>l</code>, of the random exponent (private
     * value).
     *
     * @return the size in bits, <code>l</code>, of the random exponent (private
     * value), or 0 if this size has not been set
     */
    public int getL() {
        return this.l;
    }

    /**
     * @return the keySize
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * @return the kyberKeySize
     */
    public KyberKeySize getKyberKeySize() {
        return kyberKeySize;
    }
}
