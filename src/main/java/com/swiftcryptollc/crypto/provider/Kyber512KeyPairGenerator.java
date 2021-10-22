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
public final class Kyber512KeyPairGenerator extends KeyPairGeneratorSpi {

    private KyberParameterSpec params;
    private final KyberKeySize kyberKeySize = KyberKeySize.KEY_512;
    private SecureRandom random;

    public Kyber512KeyPairGenerator() {
        super();
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize != 512) {
            throw new InvalidParameterException(
                    "Kyber key size must be 512. "
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
        KyberPKI kyberPKI = generateKeys512(random);
        return new KeyPair(kyberPKI.getPublicKey(), kyberPKI.getPrivateKey());
    }

    /**
     * Generate a 512 public/private key set
     */
    private KyberPKI generateKeys512(SecureRandom rand) {
        int paramsK = 2;
        KyberPKI kyberPKI = new KyberPKI();
        try {
            KyberPackedPKI indcpaPKI = Indcpa.generateKyberKeys(paramsK);
            byte[] packedPublicKey = indcpaPKI.getPackedPublicKey();
            byte[] packedPrivateKey = indcpaPKI.getPackedPrivateKey();
            byte[] privateKeyFixedLength = new byte[KyberParams.Kyber512SKBytes];
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
            System.out.println("generateKeys512 Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
        return kyberPKI;
    }
}
