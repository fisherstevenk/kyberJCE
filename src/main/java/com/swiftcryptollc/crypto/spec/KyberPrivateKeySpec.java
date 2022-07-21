package com.swiftcryptollc.crypto.spec;

import com.swiftcryptollc.crypto.provider.KyberKeySize;
import java.math.BigInteger;

/**
 * Helper class for the Kyber Private Key
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public final class KyberPrivateKeySpec implements java.security.spec.KeySpec {

    // The private value
    private byte[] x;

    // The prime modulus
    private BigInteger p;

    // The base generator
    private BigInteger g;

    private KyberKeySize kyberKeySize;

    /**
     * Constructor that takes a private value <code>x</code>, a prime modulus
     * <code>p</code>, and a base generator <code>g</code>.
     *
     * @param x private value x
     * @param p prime modulus p
     * @param g base generator g
     */
    public KyberPrivateKeySpec(byte[] x, BigInteger p, BigInteger g, KyberKeySize kyberKeySize) {
        this.kyberKeySize = kyberKeySize;
        this.x = x;
        this.p = p;
        this.g = g;
    }

    /**
     * Returns the private value <code>x</code>.
     *
     * @return the private value <code>x</code>
     */
    public byte[] getX() {
        return this.x;
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
     * @return the kyberKeySize
     */
    public KyberKeySize getKyberKeySize() {
        return kyberKeySize;
    }

    /**
     * @param kyberKeySize the kyberKeySize to set
     */
    protected void setKyberKeySize(KyberKeySize kyberKeySize) {
        this.kyberKeySize = kyberKeySize;
    }
}
