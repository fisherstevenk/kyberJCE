package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.provider.kyber.KyberParams;
import com.swiftcryptollc.crypto.spec.KyberParameterSpec;
import com.swiftcryptollc.crypto.util.KyberKeyUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.util.Objects;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;

/**
 * A private key in PKCS#8 format for the Diffie-Hellman key agreement
 * algorithm.
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
final class KyberPrivateKey implements PrivateKey, com.swiftcryptollc.crypto.interfaces.KyberPrivateKey, Serializable {

    static final long serialVersionUID = 437565672797198821L;

    private KyberKeySize kyberKeySize;

    // only supported version of PKCS#8 PrivateKeyInfo
    private static final BigInteger PKCS8_VERSION = BigInteger.ZERO;

    // the private key
    private byte[] x;

    // the key bytes, without the algorithm information
    private byte[] key;

    // the encoded key
    private byte[] encodedKey;

    // the prime modulus
    private BigInteger p;

    // the base generator
    private BigInteger g;

    // the private-value length (optional)
    private int l;

    /**
     * Make a Kyber private key out of a private value <code>x</code>, a prime
     * modulus <code>p</code>, and a base generator <code>g</code>.
     *
     * @param x the private value
     * @param p the prime modulus
     * @param g the base generator
     *
     * @exception ProviderException if the key cannot be encoded
     */
    KyberPrivateKey(byte[] x, BigInteger p, BigInteger g)
            throws InvalidKeyException {
        this(x, p, g, x.length);
    }

    /**
     * Make a Kyber private key out of a private value <code>x</code>, a prime
     * modulus <code>p</code>, a base generator <code>g</code>, and a
     * private-value length <code>l</code>.
     *
     * @param x the private value
     * @param p the prime modulus
     * @param g the base generator
     * @param l the private-value length
     *
     * @exception InvalidKeyException if the key cannot be encoded
     */
    KyberPrivateKey(byte[] x, BigInteger p, BigInteger g, int l)
            throws InvalidKeyException {
        this.kyberKeySize = KyberKeyUtil.getKyberKeySizePrivateKey(x.length);
        this.x = x.clone();
        if (p == null) {
            this.p = KyberParams.default_p;
        }
        this.g = g;
        if (g == null) {
            this.g = KyberParams.default_g;
        }
        this.l = l;
        try {
            this.key = new DerValue(DerValue.tag_Integer,
                    this.getX()).toByteArray();
            this.encodedKey = getEncoded();
        } catch (IOException e) {
            throw new ProviderException("Cannot produce ASN.1 encoding", e);
        }
    }

    /**
     * Make a Kyber private key from its DER encoding (PKCS #8).
     *
     * @param encodedKey the encoded key
     *
     * @exception InvalidKeyException if the encoded key does not represent a
     * Diffie-Hellman private key
     */
    KyberPrivateKey(byte[] encodedKey) throws InvalidKeyException {
        InputStream inStream = new ByteArrayInputStream(encodedKey);
        try {
            DerValue val = new DerValue(inStream);
            if (val.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Key not a SEQUENCE");
            }

            //
            // version
            //
            BigInteger parsedVersion = val.data.getBigInteger();
            if (!parsedVersion.equals(PKCS8_VERSION)) {
                throw new IOException("version mismatch: (supported: "
                        + PKCS8_VERSION + ", parsed: "
                        + parsedVersion);
            }

            //
            // privateKeyAlgorithm
            //
            DerValue algid = val.data.getDerValue();
            if (algid.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("AlgId is not a SEQUENCE");
            }
            DerInputStream derInStream = algid.toDerInputStream();
            ObjectIdentifier oid = derInStream.getOID();
            if (oid == null) {
                throw new InvalidKeyException("Null OID");
            }
            if (derInStream.available() == 0) {
                throw new InvalidKeyException("Parameters missing");
            }
            // parse the parameters
            DerValue params = derInStream.getDerValue();
            if (params.tag == DerValue.tag_Null) {
                throw new InvalidKeyException("Null parameters");
            }
            if (params.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Parameters not a SEQUENCE");
            }
            params.data.reset();
            this.p = params.data.getBigInteger();
            this.g = params.data.getBigInteger();
            // Private-value length is OPTIONAL
            if (params.data.available() != 0) {
                this.l = params.data.getInteger();
            }
            if (params.data.available() != 0) {
                throw new InvalidKeyException("Extra parameter data");
            }

            //
            // privateKey
            //
            this.key = val.data.getOctetString();
            parseKeyBits();

            this.encodedKey = new byte[encodedKey.length];
            System.arraycopy(encodedKey, 0, this.encodedKey, 0, encodedKey.length);
        } catch (IOException | NumberFormatException e) {
            throw new InvalidKeyException("Error parsing key encoding", e);
        }
    }

    /**
     * Returns the encoding format of this key: "PKCS#8"
     */
    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Returns the name of the algorithm associated with this key: "Kyber"
     */
    @Override
    public String getAlgorithm() {
        return "Kyber";
    }

    /**
     * Get the encoding of the key.
     */
    @Override
    public synchronized byte[] getEncoded() {
        if (this.encodedKey == null) {
            try {
                DerOutputStream tmp = new DerOutputStream();

                //
                // version
                //
                tmp.putInteger(PKCS8_VERSION);

                //
                // privateKeyAlgorithm
                //
                DerOutputStream algid = new DerOutputStream();

                // store OID
                algid.putOID(ObjectIdentifier.of(KyberJCE.OID_KYBER));
                // encode parameters
                DerOutputStream params = new DerOutputStream();
                params.putInteger(this.p);
                params.putInteger(this.g);
                if (this.l != 0) {
                    params.putInteger(this.l);
                }
                // wrap parameters into SEQUENCE
                DerValue paramSequence = new DerValue(DerValue.tag_Sequence,
                        params.toByteArray());
                // store parameter SEQUENCE in algid
                algid.putDerValue(paramSequence);
                // wrap algid into SEQUENCE
                tmp.write(DerValue.tag_Sequence, algid);

                // privateKey
                tmp.putOctetString(this.key);

                // make it a SEQUENCE
                DerOutputStream derKey = new DerOutputStream();
                derKey.write(DerValue.tag_Sequence, tmp);
                byte[] tempArray = derKey.toByteArray();
                this.encodedKey = new byte[tempArray.length];
                System.arraycopy(tempArray, 0, this.encodedKey, 0, tempArray.length);
            } catch (IOException e) {
                return null;
            }
        }
        byte[] newKey = new byte[encodedKey.length];
        System.arraycopy(encodedKey, 0, newKey, 0, encodedKey.length);

        return newKey;
    }

    /**
     * Returns the private value, <code>y</code>.
     *
     * @return the private value, <code>y</code>
     */
    @Override
    public byte[] getX() {
        return this.x.clone();
    }

    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    @Override
    public KyberParameterSpec getParams() {
        return new KyberParameterSpec(this.p, this.g, this.l);
    }

    /**
     * Parse the encoded key into the original raw key
     *
     * @throws InvalidKeyException
     */
    private void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(this.key);
            byte[] rawArray = in.toByteArray();
            this.x = new byte[rawArray.length - 4];
            System.arraycopy(rawArray, 4, this.x, 0, rawArray.length - 4);
            this.kyberKeySize = KyberKeyUtil.getKyberKeySizePrivateKey(x.length);
            this.l = this.x.length;
        } catch (IOException e) {
            throw new InvalidKeyException(
                    "Error parsing key encoding: " + e.getMessage());
        }
    }

    /**
     * Calculates a hash code value for\ the object. Objects that are equal will
     * also have the same hashcode.
     */
    @Override
    public int hashCode() {
        return Objects.hash(x, p, g);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof KyberPrivateKey)) {
            return false;
        }
        KyberPrivateKey other
                = (KyberPrivateKey) obj;
        KyberParameterSpec otherParams = other.getParams();
        return ((KyberKeyUtil.constantTimeCompare(this.x, other.getX()) == 0)
                && (this.p.compareTo(otherParams.getP()) == 0)
                && (this.g.compareTo(otherParams.getG()) == 0));
    }

    /**
     * Replace the Kyber private key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException if a new object representing this
     * Kyber private key could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PRIVATE,
                getAlgorithm(),
                getFormat(),
                getEncoded());
    }

    /**
     * @return the kyberKeySize
     */
    @Override
    public KyberKeySize getKyberKeySize() {
        return kyberKeySize;
    }

    /**
     * @param kyberKeySize the kyberKeySize to set
     */
    protected void setKyberKeySize(KyberKeySize kyberKeySize) {
        this.kyberKeySize = kyberKeySize;
    }
}
