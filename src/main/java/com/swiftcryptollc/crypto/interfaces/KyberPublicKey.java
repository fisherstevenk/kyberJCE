package com.swiftcryptollc.crypto.interfaces;

import com.swiftcryptollc.crypto.provider.KyberKeySize;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public interface KyberPublicKey extends KyberKey, java.security.PublicKey {

    static final long serialVersionUID = -2187346178259912349L;

    /**
     * Returns the public value, <code>y</code>.
     *
     * @return the public value, <code>y</code>
     */
    public byte[] getY();

    public KyberKeySize getKyberKeySize();
}
