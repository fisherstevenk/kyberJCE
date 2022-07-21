package com.swiftcryptollc.crypto.provider;

/**
 * Helper class for the Cipher Text
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public final class KyberVariant {

    private final byte[] plainText;

    /**
     * Default Constructor
     *
     * @param plainText
     */
    public KyberVariant(byte[] plainText) {
        this.plainText = new byte[plainText.length];
        System.arraycopy(plainText, 0, this.plainText, 0, plainText.length);
    }

    /**
     * Get the raw bytes
     *
     * @return
     */
    public byte[] getBytes() {
        return plainText;
    }
}
