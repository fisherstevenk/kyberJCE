package com.swiftcryptollc.crypto.spec;

import com.swiftcryptollc.crypto.provider.KyberKeySize;
import java.math.BigInteger;

/**
 * Helper class for the Kyber Public Key
 *
 * Should encrypt the key like KyberPublicKey
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public final class KyberPublicKeySpec implements java.security.spec.KeySpec {

    // The public value
    private byte[] y;

    // The prime modulus
    private BigInteger p;

    // The base generator
    private BigInteger g;

    private KyberKeySize kyberKeySize;

    /**
     * Constructor that takes a public value <code>y</code>, a prime modulus
     * <code>p</code>, and a base generator <code>g</code>.
     *
     * @param y public value y
     * @param p prime modulus p
     * @param g base generator g
     */
    public KyberPublicKeySpec(byte[] y, BigInteger p, BigInteger g, KyberKeySize kyberKeySize) {
        this.kyberKeySize = kyberKeySize;
        this.y = y;
        this.p = p;
        this.g = g;
    }

    /**
     * Returns the public value, <code>y</code>.
     *
     * @return the public value, <code>y</code>
     */
    public byte[] getY() {
        return y;
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
