package com.swiftcryptollc.crypto.provider;

/**
 * Kyber PKI Helper class
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
final class KyberPKI {

    private KyberPrivateKey privateKey;
    private KyberPublicKey publicKey;

    /**
     *  Default Constructor
     */
    public KyberPKI() {

    }

    /**
     * @return the privateKey
     */
    public KyberPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @param privateKey the privateKey to set
     */
    public void setPrivateKey(KyberPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * @return the publicKey
     */
    public KyberPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * @param publicKey the publicKey to set
     */
    public void setPublicKey(KyberPublicKey publicKey) {
        this.publicKey = publicKey;
    }

}
