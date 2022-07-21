package com.swiftcryptollc.crypto.interfaces;

import com.swiftcryptollc.crypto.spec.KyberParameterSpec;

/**
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public interface KyberKey {

    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    public KyberParameterSpec getParams();
}
