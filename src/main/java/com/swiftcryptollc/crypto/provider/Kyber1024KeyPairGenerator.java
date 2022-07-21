package com.swiftcryptollc.crypto.provider;

import com.github.aelstad.keccakj.fips202.SHA3_256;
import com.swiftcryptollc.crypto.provider.kyber.Indcpa;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;
import com.swiftcryptollc.crypto.spec.KyberParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public final class Kyber1024KeyPairGenerator extends KeyPairGeneratorSpi {

    private KyberParameterSpec params;
    private final KyberKeySize kyberKeySize = KyberKeySize.KEY_1024;
    private SecureRandom random;

    public Kyber1024KeyPairGenerator() {
        super();
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize != 1024) {
            throw new InvalidParameterException(
                    "Kyber key size must be 1024. "
                    + "The specific key size " + keySize + " is not supported");
        }
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec algParams,
            SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(algParams instanceof KyberParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Inappropriate parameter type");
        }
        params = (KyberParameterSpec) algParams;
        if (params.getKyberKeySize() != this.kyberKeySize) {
            throw new InvalidAlgorithmParameterException("Invalid key size!");
        }

        this.random = random;
    }

    /**
     * Generates a key pair.
     *
     * @return the new key pair
     */
    @Override
    public KeyPair generateKeyPair() {
        try {
            if (random == null) {
                random = SecureRandom.getInstanceStrong();
            }

        } catch (Exception ex) {

        }
        KyberPKI kyberPKI = generateKeys1024(random);
        return new KeyPair(kyberPKI.getPublicKey(), kyberPKI.getPrivateKey());
    }

    /**
     * Generate a 1024 public/private key set
     */
    private KyberPKI generateKeys1024(SecureRandom rand) {
        KyberPKI kyberPKI = new KyberPKI();
        int paramsK = 4;
        try {
            KyberPackedPKI indcpaPKI = Indcpa.generateKyberKeys(paramsK);
            byte[] packedPrivateKey = indcpaPKI.getPackedPrivateKey();
            byte[] packedPublicKey = indcpaPKI.getPackedPublicKey();
            byte[] privateKeyFixedLength = new byte[KyberParams.Kyber1024SKBytes];
            MessageDigest md = new SHA3_256();

            byte[] encodedHash = md.digest(packedPublicKey);
            byte[] pkh = new byte[encodedHash.length];
            System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.length);
            byte[] rnd = new byte[KyberParams.paramsSymBytes];
            rand.nextBytes(rnd);

            int offsetEnd = packedPrivateKey.length;
            System.arraycopy(packedPrivateKey, 0, privateKeyFixedLength, 0, offsetEnd);
            System.arraycopy(packedPublicKey, 0, privateKeyFixedLength, offsetEnd, packedPublicKey.length);
            offsetEnd = offsetEnd + packedPublicKey.length;

            System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.length);
            offsetEnd += pkh.length;
            System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.length);
            kyberPKI.setPublicKey(new KyberPublicKey(packedPublicKey, null, null));
            kyberPKI.setPrivateKey(new KyberPrivateKey(privateKeyFixedLength, null, null));
        } catch (Exception ex) {
            System.out.println("generateKeys1024 Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
        return kyberPKI;
    }

}
