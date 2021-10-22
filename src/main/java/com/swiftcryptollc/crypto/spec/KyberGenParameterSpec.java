package com.swiftcryptollc.crypto.spec;

import com.swiftcryptollc.crypto.provider.KyberKeySize;
import java.security.spec.AlgorithmParameterSpec;

public final class KyberGenParameterSpec implements AlgorithmParameterSpec {

    private final int keySize;
    private final KyberKeySize kyberKeySize;

    public KyberGenParameterSpec() {
        this.keySize = 768;// default
        this.kyberKeySize = KyberKeySize.KEY_768;
    }

    public KyberGenParameterSpec(int keySize) {
        this.keySize = keySize;
        if (keySize == 512) {
            this.kyberKeySize = KyberKeySize.KEY_512;
        } else if (keySize == 768) {
            this.kyberKeySize = KyberKeySize.KEY_768;
        } else {
            this.kyberKeySize = KyberKeySize.KEY_1024;
        }
    }

    /**
     * Returns the size in bytes of the key size.
     *
     * @return the size in bytes of the key size
     */
    public int getKeySize() {
        return this.keySize;
    }

    /**
     * @return the kyberKeySize
     */
    public KyberKeySize getKyberKeySize() {
        return kyberKeySize;
    }
}
