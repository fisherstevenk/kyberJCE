package com.swiftcryptollc.crypto.provider;

import java.security.AccessController;
import java.security.Provider;
import java.security.SecureRandom;
import static sun.security.util.SecurityConstants.PROVIDER_VER;

/**
 * Java implementation of the CRYSTALS Kyber Algorithm.
 *
 * The code is mostly based on the Go implementation of Kyber found here:
 * https://github.com/SymbolicSoft/kyber-k2so
 *
 * The structure of the code is based on Sun's Diffie-Hellman implementation.
 *
 * Version 1.0 Compiled with Java 13 for Android compatibility.
 * Version 2.0 Compiled with Java 18.
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public final class KyberJCE extends Provider {

    private static final long serialVersionUID = 387564738298475632L;
    public static final String OID_KYBER = "1.3.6.1.4.1.2.267.8";

    private static final String info = "KyberJCE Provider "
            + "(implements CRYSTALS Kyber)";

    /* Are we debugging? -- for developers */
    static final boolean debug = false;

    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile KyberJCE instance;

    // lazy initialize SecureRandom to avoid potential recursion if Sun
    // provider has not been installed yet
    private static class SecureRandomHolder {

        static final SecureRandom RANDOM = new SecureRandom();
    }

    static SecureRandom getRandom() {
        return SecureRandomHolder.RANDOM;
    }

    public KyberJCE() {
        super("KyberJCE", PROVIDER_VER, info);

        AccessController.doPrivileged(new java.security.PrivilegedAction<Object>() {
            @Override
            public Object run() {
                /*
                     * Key(pair) Generator engines
                 */
                put("KeyPairGenerator.Kyber512",
                        "com.swiftcryptollc.crypto.provider.Kyber512KeyPairGenerator");
                put("Alg.Alias.KeyPairGenerator.Kyber512", "Kyber512");
                put("KeyPairGenerator.Kyber768",
                        "com.swiftcryptollc.crypto.provider.Kyber768KeyPairGenerator");
                put("Alg.Alias.KeyPairGenerator.Kyber768", "Kyber768");
                put("KeyPairGenerator.Kyber1024",
                        "com.swiftcryptollc.crypto.provider.Kyber1024KeyPairGenerator");
                put("Alg.Alias.KeyPairGenerator.Kyber1024", "Kyber1024");
               put("KeyPairGenerator.Kyber",
                        "com.swiftcryptollc.crypto.provider.Kyber768KeyPairGenerator");
                put("Alg.Alias.KeyPairGenerator.Kyber", "Kyber");

                /*
                     * Algorithm parameter generation engines
                 */
                put("AlgorithmParameterGenerator.Kyber",
                        "com.swiftcryptollc.crypto.provider.KyberParameterGenerator");
                put("Alg.Alias.AlgorithmParameterGenerator.Kyber", "Kyber");
                put("Alg.Alias.KeyPairGenerator.OID." + OID_KYBER,
                        "Kyber");
                put("Alg.Alias.KeyPairGenerator." + OID_KYBER,
                        "Kyber");

                /*
                     * Key Agreement engines
                 */
                put("KeyAgreement.Kyber",
                        "com.swiftcryptollc.crypto.provider.KyberKeyAgreement");
                put("Alg.Alias.KeyAgreement.Kyber", "Kyber");

                put("KeyAgreement.Kyber SupportedKeyClasses",
                        "com.swiftcryptollc.crypto.interfaces.KyberPublicKey"
                        + "|com.swiftcryptollc.crypto.interfaces.KyberPrivateKey");

                /*
                     * Algorithm Parameter engines
                 */
                put("AlgorithmParameters.Kyber",
                        "com.swiftcryptollc.crypto.provider.KyberParameterGenerator");
                put("Alg.Alias.AlgorithmParameters.Kyber", "Kyber");

                /*
                     * Key factories
                 */
                put("KeyFactory.Kyber",
                        "com.swiftcryptollc.crypto.provider.KyberKeyFactory");
                put("Alg.Alias.KeyFactory.Kyber", "Kyber");
                put("Alg.Alias.KeyFactory.OID." + OID_KYBER,
                        "Kyber");
                put("Alg.Alias.KeyFactory." + OID_KYBER, "Kyber");

                return null;
            }
        });

        if (instance == null) {
            instance = this;
        }
    }

    // Return the instance of this class or create one if needed.
    static KyberJCE getInstance() {
        if (instance == null) {
            return new KyberJCE();
        }
        return instance;
    }
}
