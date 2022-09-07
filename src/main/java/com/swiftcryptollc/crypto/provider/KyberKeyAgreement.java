package com.swiftcryptollc.crypto.provider;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.SHA3_256;
import com.github.aelstad.keccakj.fips202.SHA3_512;
import com.github.aelstad.keccakj.fips202.Shake256;
import com.swiftcryptollc.crypto.provider.kyber.Indcpa;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;
import com.swiftcryptollc.crypto.spec.KyberParameterSpec;
import com.swiftcryptollc.crypto.util.KyberKeyUtil;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

/**
 * This class implements the Kyber key agreement protocol between any number of
 * parties.
 */
public final class KyberKeyAgreement extends KeyAgreementSpi {

    private KyberKeySize kyberKeySize;
    private BigInteger init_p = null;
    private BigInteger init_g = null;
    private byte[] x = new byte[0]; // the private value
    private byte[] y = new byte[0];
    private KyberCipherText kyberCipherText;
    private byte[] rnd = new byte[KyberParams.paramsSymBytes];

    /**
     * Empty constructor
     */
    public KyberKeyAgreement() {
    }

    /**
     * Initialize with a Kyber Private Key
     *
     * @param key
     * @throws InvalidKeyException
     */
    public void engineInit(Key key)
            throws InvalidKeyException {
        try {
            engineInit(key, null, null);
        } catch (Exception ex) {
            // never happens, because we did not pass any parameters
        }
    }

    /**
     * Initialize with a Kyber Private Key and the specified secure random
     *
     * @param key
     * @param random
     * @throws InvalidKeyException
     */
    @Override
    public void engineInit(Key key, SecureRandom random)
            throws InvalidKeyException {
        try {
            engineInit(key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // never happens, because we did not pass any parameters
        }
    }

    /**
     * Initialize with a Kyber Private Key, the given algorithm specs and the
     * given random
     *
     * @param key
     * @param params
     * @param random
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    @Override
    public void engineInit(Key key, AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if ((params != null) && !(params instanceof KyberParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Kyber parameters expected");
        }
        if (!(key instanceof com.swiftcryptollc.crypto.interfaces.KyberPrivateKey)) {
            throw new InvalidKeyException("Kyber private key "
                    + "expected");
        }

        init_p = null;
        init_g = null;

        if (random == null) {
            try {
                SecureRandom rand = SecureRandom.getInstanceStrong();
                rand.nextBytes(rnd);
            } catch (Exception ex) {

            }
        } else {
            random.nextBytes(rnd);
        }
        com.swiftcryptollc.crypto.interfaces.KyberPrivateKey kyberPrivKey;
        kyberPrivKey = (com.swiftcryptollc.crypto.interfaces.KyberPrivateKey) key;
        this.kyberKeySize = KyberKeyUtil.getKyberKeySizePrivateKey(kyberPrivKey.getX().length);
        // check if private key parameters are compatible with
        // initialized ones
        if (params != null) {
            init_p = ((KyberParameterSpec) params).getP();
            init_g = ((KyberParameterSpec) params).getG();
        }
        BigInteger priv_p = kyberPrivKey.getParams().getP();
        BigInteger priv_g = kyberPrivKey.getParams().getG();
        if (init_p != null && priv_p != null && !(init_p.equals(priv_p))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if (init_g != null && priv_g != null && !(init_g.equals(priv_g))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if ((init_p == null && priv_p == null)
                || (init_g == null && priv_g == null)) {
            throw new InvalidKeyException("Missing parameters");
        }
        init_p = priv_p;
        init_g = priv_g;

        // store the x value
        this.x = kyberPrivKey.getX();
    }

    /**
     * If a KyberPublicKey is passed and lastPhase is true, returns a
     * KyberEncrypted Object which has the shared secret key and cipher text
     *
     * If a KyberCipherText is passed, returns a KyberDecrypted Object which has
     * the shared secret key
     *
     * @param key
     * @param lastPhase
     * @return
     * @throws InvalidKeyException
     * @throws IllegalStateException
     */
    @Override
    public Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (init_p == null || init_g == null) {
            throw new IllegalStateException("Not initialized");
        }

        if (key instanceof com.swiftcryptollc.crypto.interfaces.KyberPublicKey) {
            com.swiftcryptollc.crypto.interfaces.KyberPublicKey kyberPubKey;
            kyberPubKey = (com.swiftcryptollc.crypto.interfaces.KyberPublicKey) key;

            // check if public key parameters are compatible with
            // initialized ones
            BigInteger pub_p = kyberPubKey.getParams().getP();
            BigInteger pub_g = kyberPubKey.getParams().getG();
            if (pub_p != null && !(init_p.equals(pub_p))) {
                throw new InvalidKeyException("Incompatible parameters");
            }
            if (pub_g != null && !(init_g.equals(pub_g))) {
                throw new InvalidKeyException("Incompatible parameters");
            }

            // validate the Kyber public key
            KyberKeyUtil.validate(kyberPubKey);

            // store the y value
            this.y = kyberPubKey.getY();

            // we've received a public key (from one of the other parties),
            // so we are ready to create the secret, which may be an
            // intermediate secret, in which case we wrap it into a
            // Kyber public key object and return it.
            if (lastPhase == true) {
                byte[] sharedSecret = engineGenerateSecret();
                KyberSecretKey kyberSecretKey = new KyberSecretKey(sharedSecret,
                        init_p, init_g);

                return new KyberEncrypted(kyberSecretKey, kyberCipherText);
            } else {
                return null;
            }
        } else if (key instanceof com.swiftcryptollc.crypto.provider.KyberCipherText) {
            return decrypt(kyberKeySize, (KyberCipherText) key);
        }
        throw new InvalidKeyException("Expected a KyberPublicKey or KyberCipherText");
    }

    /**
     * Generates the shared secret and returns it in a new buffer.
     *
     * <p>
     * This method resets this <code>KeyAgreementSpi</code> object, so that it
     * can be reused for further key agreements. Unless this key agreement is
     * reinitialized with one of the <code>engineInit</code> methods, the same
     * private information and algorithm parameters will be used for subsequent
     * key agreements.
     *
     * @return the new buffer with the shared secret
     *
     * @exception IllegalStateException if this key agreement has not been
     * completed yet
     */
    @Override
    protected byte[] engineGenerateSecret()
            throws IllegalStateException {
        byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
        try {
            engineGenerateSecret(sharedSecret, 0);
        } catch (ShortBufferException sbe) {
            // should never happen since length are identical
        }
        return sharedSecret;
    }

    /**
     * Generates the shared secret, and places it into the buffer
     * <code>sharedSecret</code>, beginning at <code>offset</code>.
     *
     * <p>
     * If the <code>sharedSecret</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown. In this case, this call
     * should be repeated with a larger output buffer.
     *
     * <p>
     * This method resets this <code>KeyAgreementSpi</code> object, so that it
     * can be reused for further key agreements. Unless this key agreement is
     * reinitialized with one of the <code>engineInit</code> methods, the same
     * private information and algorithm parameters will be used for subsequent
     * key agreements.
     *
     * @param sharedSecret the buffer for the shared secret
     * @param offset the offset in <code>sharedSecret</code> where the shared
     * secret will be stored
     *
     * @return the number of bytes placed into <code>sharedSecret</code>
     *
     * @exception IllegalStateException if this key agreement has not been
     * completed yet
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the secret
     */
    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        KyberEncrypted kyberEncrypted = encrypt();
        byte[] tempSecret = kyberEncrypted.getSecretKey().getS();
        System.arraycopy(tempSecret, 0, sharedSecret, 0, tempSecret.length);
        kyberCipherText = kyberEncrypted.getCipherText();
        return KyberParams.paramsSymBytes;
    }

    /**
     * Creates the shared secret and returns it as a secret key object of the
     * requested algorithm type.
     *
     * <p>
     * This method resets this <code>KeyAgreementSpi</code> object, so that it
     * can be reused for further key agreements. Unless this key agreement is
     * reinitialized with one of the <code>engineInit</code> methods, the same
     * private information and algorithm parameters will be used for subsequent
     * key agreements.
     *
     * @param algorithm the requested secret key algorithm
     *
     * @return the shared secret key
     *
     * @exception IllegalStateException if this key agreement has not been
     * completed yet
     * @exception NoSuchAlgorithmException if the requested secret key algorithm
     * is not available
     * @exception InvalidKeyException if the shared secret key material cannot
     * be used to generate a secret key of the requested algorithm type (e.g.,
     * the key material is too short)
     */
    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException,
            InvalidKeyException {
        throw new NoSuchAlgorithmException("Not implemented");
    }

    /**
     * Generate a key with the give kyber key size
     *
     * @param kyberKeySize
     * @param cipherText
     * @return
     */
    public KyberDecrypted decrypt(KyberKeySize kyberKeySize, KyberCipherText cipherText) {
        switch (kyberKeySize) {
            case KEY_512:
                return this.decrypt512(cipherText);
            case KEY_1024:
                return this.decrypt1024(cipherText);
            case KEY_768:
                return this.decrypt768(cipherText);
        }
        return null;
    }

    /**
     * Get the shared secret with the given cipher text and private key
     *
     * @param kyberCiphertext
     * @return
     */
    private KyberDecrypted decrypt512(KyberCipherText kyberCiphertext) {
        byte[] ciphertext = kyberCiphertext.getC();
        byte[] privateKey = this.x;
        int paramsK = 2;
        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        byte[] indcpaPrivateKey = new byte[KyberParams.paramsIndcpaSecretKeyBytesK512];
        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.length);
        byte[] publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
        System.arraycopy(privateKey, KyberParams.paramsIndcpaSecretKeyBytesK512, publicKey, 0, publicKey.length);

        byte[] buf = Indcpa.decrypt(ciphertext, indcpaPrivateKey, paramsK);
        int ski = KyberParams.Kyber512SKBytes - 2 * KyberParams.paramsSymBytes;
        byte[] newBuf = new byte[buf.length + KyberParams.paramsSymBytes];
        System.arraycopy(buf, 0, newBuf, 0, buf.length);
        System.arraycopy(privateKey, ski, newBuf, buf.length, KyberParams.paramsSymBytes);
        MessageDigest md512 = new SHA3_512();
        byte[] kr = md512.digest(newBuf);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] cmp = Indcpa.encrypt(buf, publicKey, subKr, paramsK);
        byte fail = (byte) KyberKeyUtil.constantTimeCompare(ciphertext, cmp);
        MessageDigest md = new SHA3_256();
        byte[] krh = md.digest(ciphertext);
        int index = KyberParams.Kyber512SKBytes - KyberParams.paramsSymBytes;
        for (int i = 0; i < KyberParams.paramsSymBytes; i++) {
            kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (privateKey[index] & 0xFF))));
            index += 1;
        }
        byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
        System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(tempBuf);
        xof.getSqueezeStream().read(sharedSecretFixedLength);

        return new KyberDecrypted(new KyberSecretKey(sharedSecretFixedLength, null, null), new KyberVariant(buf));
    }

    /**
     * Get the shared secret with the given cipher text and private key
     *
     * @param kyberCiphertext
     * @return
     */
    private KyberDecrypted decrypt768(KyberCipherText kyberCiphertext) {
        byte[] ciphertext = kyberCiphertext.getC();
        byte[] privateKey = this.x;
        int paramsK = 3;
        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        byte[] indcpaPrivateKey = new byte[KyberParams.paramsIndcpaSecretKeyBytesK768];
        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.length);
        byte[] publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK768];
        System.arraycopy(privateKey, KyberParams.paramsIndcpaSecretKeyBytesK768, publicKey, 0, publicKey.length);

        byte[] buf = Indcpa.decrypt(ciphertext, indcpaPrivateKey, paramsK);
        int ski = KyberParams.Kyber768SKBytes - 2 * KyberParams.paramsSymBytes;
        byte[] newBuf = new byte[buf.length + KyberParams.paramsSymBytes];
        System.arraycopy(buf, 0, newBuf, 0, buf.length);
        System.arraycopy(privateKey, ski, newBuf, buf.length, KyberParams.paramsSymBytes);
        MessageDigest md512 = new SHA3_512();
        byte[] kr = md512.digest(newBuf);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] cmp = Indcpa.encrypt(buf, publicKey, subKr, paramsK);
        byte fail = (byte) KyberKeyUtil.constantTimeCompare(ciphertext, cmp);
        // For security purposes, removed the "if" so it behaves the same whether it
        // worked or not.
        MessageDigest md = new SHA3_256();
        byte[] krh = md.digest(ciphertext);
        int index = KyberParams.Kyber768SKBytes - KyberParams.paramsSymBytes;
        for (int i = 0; i < KyberParams.paramsSymBytes; i++) {
            kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (privateKey[index] & 0xFF))));
            index += 1;
        }
        byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
        System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(tempBuf);
        xof.getSqueezeStream().read(sharedSecretFixedLength);

        return new KyberDecrypted(new KyberSecretKey(sharedSecretFixedLength, null, null), new KyberVariant(buf));
    }

    /**
     * Get the shared secret with the given cipher text and private key
     *
     * @param kyberCiphertext
     * @return
     */
    private KyberDecrypted decrypt1024(KyberCipherText kyberCiphertext)
            throws IllegalArgumentException {
        byte[] ciphertext = kyberCiphertext.getC();
        byte[] privateKey = this.x;
        int paramsK = 4;
        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        byte[] indcpaPrivateKey = new byte[KyberParams.paramsIndcpaSecretKeyBytesK1024];
        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.length);
        byte[] publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
        System.arraycopy(privateKey, KyberParams.paramsIndcpaSecretKeyBytesK1024, publicKey, 0, publicKey.length);

        byte[] buf = Indcpa.decrypt(ciphertext, indcpaPrivateKey, paramsK);
        int ski = KyberParams.Kyber1024SKBytes - 2 * KyberParams.paramsSymBytes;
        byte[] newBuf = new byte[buf.length + KyberParams.paramsSymBytes];
        System.arraycopy(buf, 0, newBuf, 0, buf.length);
        System.arraycopy(privateKey, ski, newBuf, buf.length, KyberParams.paramsSymBytes);
        MessageDigest md512 = new SHA3_512();
        byte[] kr = md512.digest(newBuf);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] cmp = Indcpa.encrypt(buf, publicKey, subKr, paramsK);
        byte fail = (byte) KyberKeyUtil.constantTimeCompare(ciphertext, cmp);
        // For security purposes, removed the "if" so it behaves the same whether it
        // worked or not.
        MessageDigest md = new SHA3_256();
        byte[] krh = md.digest(ciphertext);
        int index = KyberParams.Kyber1024SKBytes - KyberParams.paramsSymBytes;
        for (int i = 0; i < KyberParams.paramsSymBytes; i++) {
            kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (privateKey[index] & 0xFF))));
            index += 1;
        }
        byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
        System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(tempBuf);
        xof.getSqueezeStream().read(sharedSecretFixedLength);

        return new KyberDecrypted(new KyberSecretKey(sharedSecretFixedLength, null, null), new KyberVariant(buf));
    }

    /**
     * Generate a key with the give kyber key size
     *
     * @return
     */
    private KyberEncrypted encrypt() {
        try {
            switch (kyberKeySize) {
                case KEY_512:
                    return this.encrypt512(rnd, this.y);
                case KEY_1024:
                    return this.encrypt1024(rnd, this.y);
                case KEY_768:
                    return this.encrypt768(rnd, this.y);
            }
        } catch (Exception ex) {
            System.out.println("Exception during encrypt! [" + ex.getMessage() + "]");
            ex.printStackTrace();
            return null;
        }
        return null;
    }

    /**
     * Encrypt the given data with the given public key
     *
     * @param variant
     * @param kyberPublicKey
     * @return KyberEncrypted
     */
    private KyberEncrypted encrypt512(byte[] variant, byte[] publicKey) throws IllegalArgumentException {
        variant = verifyVariant(variant);
        KyberEncrypted msg = new KyberEncrypted();
        int paramsK = 2;
        //   byte[] ciphertextFixedLength = new byte[KyberParams.Kyber512CTBytes];
        //  byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        try {
            byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
            MessageDigest md = new SHA3_256();
            byte[] buf1 = md.digest(variant);
            byte[] buf2 = md.digest(publicKey);
            byte[] buf3 = new byte[buf1.length + buf2.length];
            System.arraycopy(buf1, 0, buf3, 0, buf1.length);
            System.arraycopy(buf2, 0, buf3, buf1.length, buf2.length);
            MessageDigest md512 = new SHA3_512();
            byte[] kr = md512.digest(buf3);
            byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
            System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
            byte[] ciphertext = Indcpa.encrypt(buf1, publicKey, subKr, paramsK);
            byte[] krc = md.digest(ciphertext);
            byte[] newKr = new byte[KyberParams.paramsSymBytes + krc.length];
            System.arraycopy(kr, 0, newKr, 0, KyberParams.paramsSymBytes);
            System.arraycopy(krc, 0, newKr, KyberParams.paramsSymBytes, krc.length);
            KeccakSponge xof = new Shake256();
            xof.getAbsorbStream().write(newKr);
            xof.getSqueezeStream().read(sharedSecret);
            //     System.arraycopy(ciphertext, 0, ciphertextFixedLength, 0, ciphertext.length);
            //   System.arraycopy(sharedSecret, 0, sharedSecretFixedLength, 0, sharedSecret.length);
            msg.setCipherText(new KyberCipherText(ciphertext, null, null));
            msg.setSecretKey(new KyberSecretKey(sharedSecret, null, null));
        } catch (Exception ex) {
            System.out.println("KemEncrypt512 Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
        return msg;
    }

    /**
     * Encrypt the given data with the public key
     *
     * @param variant
     * @param kyberPublicKey
     * @return KyberEncrypted
     */
    private KyberEncrypted encrypt768(byte[] variant, byte[] publicKey) {
        variant = verifyVariant(variant);
        KyberEncrypted msg = new KyberEncrypted();
        int paramsK = 3;
        //byte[] ciphertextFixedLength = new byte[KyberParams.Kyber768CTBytes];
        // byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        try {
            byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
            MessageDigest md = new SHA3_256();
            byte[] buf1 = md.digest(variant);
            byte[] buf2 = md.digest(publicKey);
            byte[] buf3 = new byte[buf1.length + buf2.length];
            System.arraycopy(buf1, 0, buf3, 0, buf1.length);
            System.arraycopy(buf2, 0, buf3, buf1.length, buf2.length);
            MessageDigest md512 = new SHA3_512();
            byte[] kr = md512.digest(buf3);
            byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
            System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
            byte[] ciphertext = Indcpa.encrypt(buf1, publicKey, subKr, paramsK);
            byte[] krc = md.digest(ciphertext);
            byte[] newKr = new byte[KyberParams.paramsSymBytes + krc.length];
            System.arraycopy(kr, 0, newKr, 0, KyberParams.paramsSymBytes);
            System.arraycopy(krc, 0, newKr, KyberParams.paramsSymBytes, krc.length);
            KeccakSponge xof = new Shake256();
            xof.getAbsorbStream().write(newKr);
            xof.getSqueezeStream().read(sharedSecret);
            //      System.arraycopy(ciphertext, 0, ciphertextFixedLength, 0, ciphertext.length);
            //    System.arraycopy(sharedSecret, 0, sharedSecretFixedLength, 0, sharedSecret.length);
            msg.setCipherText(new KyberCipherText(ciphertext, null, null));
            msg.setSecretKey(new KyberSecretKey(sharedSecret, null, null));
        } catch (Exception ex) {
            System.out.println("KemEncrypt768 Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
        return msg;
    }

    /**
     * Encrypt ciphertext with the public key
     *
     * @param variant
     * @param kyberPublicKey
     * @return KyberEncrypted
     */
    private KyberEncrypted encrypt1024(byte[] variant, byte[] publicKey) {
        variant = verifyVariant(variant);
        KyberEncrypted msg = new KyberEncrypted();
        int paramsK = 4;
        //    byte[] ciphertextFixedLength = new byte[KyberParams.Kyber1024CTBytes];
        //  byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        try {
            byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
            MessageDigest md = new SHA3_256();
            byte[] buf1 = md.digest(variant);
            byte[] buf2 = md.digest(publicKey);
            byte[] buf3 = new byte[buf1.length + buf2.length];
            System.arraycopy(buf1, 0, buf3, 0, buf1.length);
            System.arraycopy(buf2, 0, buf3, buf1.length, buf2.length);
            MessageDigest md512 = new SHA3_512();
            byte[] kr = md512.digest(buf3);
            byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
            System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
            byte[] ciphertext = Indcpa.encrypt(buf1, publicKey, subKr, paramsK);
            byte[] krc = md.digest(ciphertext);
            byte[] newKr = new byte[KyberParams.paramsSymBytes + krc.length];
            System.arraycopy(kr, 0, newKr, 0, KyberParams.paramsSymBytes);
            System.arraycopy(krc, 0, newKr, KyberParams.paramsSymBytes, krc.length);
            KeccakSponge xof = new Shake256();
            xof.getAbsorbStream().write(newKr);
            xof.getSqueezeStream().read(sharedSecret);
            //       System.arraycopy(ciphertext, 0, ciphertextFixedLength, 0, ciphertext.length);
            //     System.arraycopy(sharedSecret, 0, sharedSecretFixedLength, 0, sharedSecret.length);
            msg.setCipherText(new KyberCipherText(ciphertext, null, null));
            msg.setSecretKey(new KyberSecretKey(sharedSecret, null, null));
        } catch (Exception ex) {
            System.out.println("KemEncrypt1024 Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
        return msg;
    }

    /**
     * Verify the array size of the variant data
     *
     * @param variant
     * @return
     * @throws IllegalArgumentException
     */
    private byte[] verifyVariant(byte[] variant) throws IllegalArgumentException {
        if (variant.length > KyberParams.paramsSymBytes) {
            throw new IllegalArgumentException("Byte array exceeds allowable size of " + KyberParams.paramsSymBytes + " bytes");
        } else if (variant.length < KyberParams.paramsSymBytes) {
            byte[] tempData = new byte[KyberParams.paramsSymBytes];
            System.arraycopy(variant, 0, tempData, 0, variant.length);
            byte[] emptyBytes = new byte[KyberParams.paramsSymBytes - variant.length];
            for (int i = 0; i < emptyBytes.length; ++i) {
                emptyBytes[i] = (byte) 0;
            }

            System.arraycopy(emptyBytes, 0, tempData, variant.length, emptyBytes.length);
            return tempData;
        }
        return variant;
    }
}
