package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.spec.KyberParameterSpec;
import com.swiftcryptollc.crypto.spec.KyberPrivateKeySpec;
import com.swiftcryptollc.crypto.spec.KyberPublicKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * This class implements the Kyber key factory
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 *
 */
public final class KyberKeyFactory extends KeyFactorySpi {

    /**
     * Empty constructor
     */
    public KyberKeyFactory() {
    }

    /**
     * Generates a public key object from the provided key specification (key
     * material).
     *
     * @param keySpec the specification (key material) of the public key
     *
     * @return the public key
     *
     * @exception InvalidKeySpecException if the given key specification is
     * inappropriate for this key factory to produce a public key.
     */
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException {
        try {
            if (keySpec instanceof KyberPublicKeySpec) {
                KyberPublicKeySpec kyberPubKeySpec = (KyberPublicKeySpec) keySpec;
                return new KyberPublicKey(kyberPubKeySpec.getY(),
                        kyberPubKeySpec.getP(),
                        kyberPubKeySpec.getG());

            } else if (keySpec instanceof X509EncodedKeySpec) {
                return new KyberPublicKey(((X509EncodedKeySpec) keySpec).getEncoded());

            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification", e);
        }
    }

    /**
     * Generates a private key object from the provided key specification (key
     * material).
     *
     * @param keySpec the specification (key material) of the private key
     *
     * @return the private key
     *
     * @exception InvalidKeySpecException if the given key specification is
     * inappropriate for this key factory to produce a private key.
     */
    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException {
        try {
            if (keySpec instanceof KyberPrivateKeySpec) {
                KyberPrivateKeySpec kyberPrivKeySpec = (KyberPrivateKeySpec) keySpec;
                return new KyberPrivateKey(kyberPrivKeySpec.getX(),
                        kyberPrivKeySpec.getP(),
                        kyberPrivKeySpec.getG());

            } else if (keySpec instanceof PKCS8EncodedKeySpec) {
                return new KyberPrivateKey(((PKCS8EncodedKeySpec) keySpec).getEncoded());

            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification", e);
        }
    }

    /**
     * Returns a specification (key material) of the given key object in the
     * requested format.
     *
     * @param key the key
     *
     * @param keySpec the requested format in which the key material shall be
     * returned
     *
     * @return the underlying key specification (key material) in the requested
     * format
     *
     * @exception InvalidKeySpecException if the requested key specification is
     * inappropriate for the given key, or the given key cannot be processed
     * (e.g., the given key has an unrecognized algorithm or format).
     */
    @Override
    protected <T extends KeySpec>
            T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        KyberParameterSpec params;

        if (key instanceof com.swiftcryptollc.crypto.interfaces.KyberPublicKey) {

            if (KyberPublicKeySpec.class.isAssignableFrom(keySpec)) {
                com.swiftcryptollc.crypto.interfaces.KyberPublicKey kyberPubKey
                        = (com.swiftcryptollc.crypto.interfaces.KyberPublicKey) key;
                params = kyberPubKey.getParams();
                return keySpec.cast(new KyberPublicKeySpec(kyberPubKey.getY(),
                        params.getP(),
                        params.getG(), kyberPubKey.getKyberKeySize()));

            } else if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));

            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }

        } else if (key instanceof com.swiftcryptollc.crypto.interfaces.KyberPrivateKey) {

            if (KyberPrivateKeySpec.class.isAssignableFrom(keySpec)) {
                com.swiftcryptollc.crypto.interfaces.KyberPrivateKey kyberPrivKey
                        = (com.swiftcryptollc.crypto.interfaces.KyberPrivateKey) key;
                params = kyberPrivKey.getParams();
                return keySpec.cast(new KyberPrivateKeySpec(kyberPrivKey.getX(),
                        params.getP(),
                        params.getG(), kyberPrivKey.getKyberKeySize()));

            } else if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));

            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }

        } else {
            throw new InvalidKeySpecException("Inappropriate key type");
        }
    }

    /**
     * Translates a key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this key factory.
     *
     * @param key the key whose provider is unknown or untrusted
     *
     * @return the translated key
     *
     * @exception InvalidKeyException if the given key cannot be processed by
     * this key factory.
     */
    @Override
    protected Key engineTranslateKey(Key key)
            throws InvalidKeyException {
        try {

            if (key instanceof com.swiftcryptollc.crypto.interfaces.KyberPublicKey) {
                // Check if key originates from this factory
                if (key instanceof com.swiftcryptollc.crypto.provider.KyberPublicKey) {
                    return key;
                }
                // Convert key to spec
                KyberPublicKeySpec kyberPubKeySpec
                        = engineGetKeySpec(key, KyberPublicKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePublic(kyberPubKeySpec);

            } else if (key instanceof com.swiftcryptollc.crypto.interfaces.KyberPrivateKey) {
                // Check if key originates from this factory
                if (key instanceof com.swiftcryptollc.crypto.provider.KyberPrivateKey) {
                    return key;
                }
                // Convert key to spec
                KyberPrivateKeySpec kyberPrivKeySpec
                        = engineGetKeySpec(key, KyberPrivateKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(kyberPrivKeySpec);

            } else {
                throw new InvalidKeyException("Wrong algorithm type");
            }

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key", e);
        }
    }
}
