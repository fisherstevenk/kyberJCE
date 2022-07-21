package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.provider.kyber.KyberParams;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 * Helper class for the decrypted shared secret and variant
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public final class KyberDecrypted implements Key {

    private KyberSecretKey secretKey;
    private KyberVariant variant;

    /**
     * Default constructor
     */
    public KyberDecrypted() {

    }

    /**
     *
     * @param secretKey
     * @param variant
     */
    public KyberDecrypted(KyberSecretKey secretKey, KyberVariant variant) {
        this.secretKey = secretKey;
        this.variant = variant;
    }

    /**
     *
     * @param encodedBytes
     * @throws InvalidKeyException
     */
    public KyberDecrypted(byte[] encodedBytes) throws InvalidKeyException {
        byte[] encodedSecret = new byte[KyberParams.KyberEncodedSSBytes];
        System.arraycopy(encodedBytes, 0, encodedSecret, 0, KyberParams.KyberEncodedSSBytes);
        this.secretKey = new KyberSecretKey(encodedSecret);

        int variantLen = encodedBytes.length - KyberParams.KyberEncodedSSBytes;
        byte[] variantBytes = new byte[variantLen];
        System.arraycopy(encodedBytes, KyberParams.KyberEncodedSSBytes, variantBytes, 0, variantLen);
        this.variant = new KyberVariant(variantBytes);
    }

    /**
     *
     * @return
     */
    @Override
    public byte[] getEncoded() {
        byte[] encodedSecret = this.secretKey.getEncoded();
        byte[] variantBytes = this.variant.getBytes();
        byte[] returnArray = new byte[encodedSecret.length + variantBytes.length];
        System.arraycopy(encodedSecret, 0, returnArray, 0, encodedSecret.length);
        System.arraycopy(variantBytes, 0, returnArray, encodedSecret.length, variantBytes.length);
        return returnArray;
    }

    /**
     * @return the secretKey
     */
    public KyberSecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * @param secretKey the secretKey to set
     */
    public void setSecretKey(KyberSecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * @return the variant
     */
    public KyberVariant getVariant() {
        return variant;
    }

    /**
     * @param variant the variant to set
     */
    public void setVariant(KyberVariant variant) {
        this.variant = variant;
    }

    @Override
    public String getAlgorithm() {
        return "Kyber";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

}
