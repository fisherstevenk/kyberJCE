package com.swiftcryptollc.crypto.interfaces;

import com.swiftcryptollc.crypto.provider.KyberKeySize;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public interface KyberPrivateKey extends KyberKey, java.security.PrivateKey {

    static final long serialVersionUID = 47572612783495691L;

    /**
     * Returns the private value, <code>x</code>.
     *
     * @return the private value, <code>x</code>
     */
    public byte[] getX();

    public KyberKeySize getKyberKeySize();
}
