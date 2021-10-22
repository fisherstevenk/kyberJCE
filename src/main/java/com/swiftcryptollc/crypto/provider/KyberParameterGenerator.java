package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.spec.KyberGenParameterSpec;
import java.security.*;
import java.security.spec.*;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public final class KyberParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private int keySize;
    private KyberKeySize kyberKeySize;
    private SecureRandom random = null;

    private static void checkKeySize(int keysize)
            throws InvalidParameterException {

        boolean supported = ((keysize == 512) || (keysize == 768) || (keysize == 1024));

        if (!supported) {
            throw new InvalidParameterException(
                    "Kyber key size must be 512, 768, or 1024. "
                    + "The specific key size " + keysize + " is not supported");
        }
    }

    @Override
    protected void engineInit(int keySize, SecureRandom random) {
        checkKeySize(keySize);
        this.random = random;
        this.keySize = keySize;
        if (keySize == 512) {
            this.kyberKeySize = KyberKeySize.KEY_512;
        } else if (keySize == 768) {
            this.kyberKeySize = KyberKeySize.KEY_768;
        } else {
            this.kyberKeySize = KyberKeySize.KEY_1024;
        }
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec,
            SecureRandom random) throws InvalidAlgorithmParameterException {

        if (!(genParamSpec instanceof KyberGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Inappropriate parameter type");
        }

        KyberGenParameterSpec kyberParamSpec = (KyberGenParameterSpec) genParamSpec;
        this.keySize = kyberParamSpec.getKeySize();
        this.kyberKeySize = kyberParamSpec.getKyberKeySize();
        try {
            checkKeySize(this.keySize);
        } catch (InvalidParameterException ipe) {
            throw new InvalidAlgorithmParameterException(ipe.getMessage());
        }

        this.random = random;
    }

    /**
     * Use the default
     *
     * @return the new AlgorithmParameters object
     */
    @Override
    protected AlgorithmParameters engineGenerateParameters() {

        try {
            if (random == null) {
                random = SecureRandom.getInstanceStrong();
            }
            KyberGenParameterSpec kyberParamSpec = new KyberGenParameterSpec();
            AlgorithmParameters algParams
                    = AlgorithmParameters.getInstance("Kyber", KyberJCE.getInstance());
            algParams.init(kyberParamSpec);

            return algParams;
        } catch (Exception ex) {
            throw new ProviderException("Unexpected exception", ex);
        }
    }
}
