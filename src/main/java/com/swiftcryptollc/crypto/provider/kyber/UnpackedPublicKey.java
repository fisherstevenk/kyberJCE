package com.swiftcryptollc.crypto.provider.kyber;

/**
 * Helper class for an unpacked public key
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
final class UnpackedPublicKey {

    private short[][] publicKeyPolyvec;
    private byte[] seed;

    /**
     * Default Constructor
     */
    public UnpackedPublicKey() {

    }

    /**
     * @return the publicKeyPolyvec
     */
    public short[][] getPublicKeyPolyvec() {
        return publicKeyPolyvec;
    }

    /**
     * @param publicKeyPolyvec the publicKeyPolyvec to set
     */
    protected void setPublicKeyPolyvec(short[][] publicKeyPolyvec) {
        this.publicKeyPolyvec = publicKeyPolyvec;
    }

    /**
     * @return the seed
     */
    public byte[] getSeed() {
        return seed;
    }

    /**
     * @param seed the seed to set
     */
    protected void setSeed(byte[] seed) {
        this.seed = seed;
    }

}
