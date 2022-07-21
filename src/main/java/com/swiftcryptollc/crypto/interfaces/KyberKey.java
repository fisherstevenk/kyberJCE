package com.swiftcryptollc.crypto.interfaces;

import com.swiftcryptollc.crypto.spec.KyberParameterSpec;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public interface KyberKey {

    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    public KyberParameterSpec getParams();
}
