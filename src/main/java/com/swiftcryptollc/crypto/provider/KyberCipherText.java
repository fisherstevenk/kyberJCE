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
import java.security.ProviderException;
import java.security.PublicKey;
import java.util.Objects;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;

/**
 * A cipher text in X.509 format for the Kyber key agreement algorithm.
 */
public final class KyberCipherText implements PublicKey, Serializable {

    static final long serialVersionUID = 2748565237750324982L;

    // the cipher text
    private byte[] c;

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

    private int Kyber_data[] = {1, 2, 840, 113549, 1, 3, 1};

    /**
     * Make a Kyber cipher text out of a public value <code>c</code>, a prime
     * modulus <code>p</code>, and a base generator <code>g</code>.
     *
     * @param c the public value
     * @param p the prime modulus
     * @param g the base generator
     *
     * @exception InvalidKeyException if the key cannot be encoded
     */
    public KyberCipherText(byte[] c, BigInteger p, BigInteger g)
            throws InvalidKeyException {
        this(c, p, g, c.length);
    }

    /**
     * Make a Kyber cipher text out of a public value <code>c</code>, a prime
     * modulus <code>p</code>, a base generator <code>g</code>, and a
     * private-value length <code>l</code>.
     *
     * @param c the public value
     * @param p the prime modulus
     * @param g the base generator
     * @param l the private-value length
     *
     * @exception ProviderException if the key cannot be encoded
     */
    public KyberCipherText(byte[] c, BigInteger p, BigInteger g, int l)
            throws InvalidKeyException {
        this.c = c.clone();
        this.p = p;
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
                    this.getC()).toByteArray();
            this.encodedKey = getEncoded();
        } catch (IOException e) {
            throw new ProviderException("Cannot produce ASN.1 encoding", e);
        }
    }

    /**
     * Make a Kyber cipher text from its DER encoding (X.509).
     *
     * @param encodedKey the encoded key
     *
     * @exception InvalidKeyException if the encoded key does not represent a
     * Kyber cipher text
     */
    public KyberCipherText(byte[] encodedKey) throws InvalidKeyException {
        InputStream inStream = new ByteArrayInputStream(encodedKey);
        try {
            DerValue derKeyVal = new DerValue(inStream);
            if (derKeyVal.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Invalid key format");
            }

            /*
             * Parse the algorithm identifier
             */
            DerValue algid = derKeyVal.data.getDerValue();
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

            /*
             * Parse the parameters
             */
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

            /*
             * Parse the key
             */
            this.key = derKeyVal.data.getBitString();
            parseKeyBits();
            if (derKeyVal.data.available() != 0) {
                throw new InvalidKeyException("Excess key data");
            }

            this.encodedKey = new byte[encodedKey.length];
            System.arraycopy(encodedKey, 0, this.encodedKey, 0, encodedKey.length);
        } catch (IOException | NumberFormatException e) {
            throw new InvalidKeyException("Error parsing key encoding", e);
        }
    }

    /**
     * Returns the encoding format of this key: "X.509"
     */
    @Override
    public String getFormat() {
        return "X.509";
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
                DerOutputStream algid = new DerOutputStream();

                // store oid in algid
                algid.putOID(new ObjectIdentifier(Kyber_data));

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

                // wrap algid into SEQUENCE, and store it in key encoding
                DerOutputStream tmpDerKey = new DerOutputStream();
                tmpDerKey.write(DerValue.tag_Sequence, algid);

                // store key data
                tmpDerKey.putBitString(this.key);

                // wrap algid and key into SEQUENCE
                DerOutputStream derKey = new DerOutputStream();
                derKey.write(DerValue.tag_Sequence, tmpDerKey);
                this.encodedKey = derKey.toByteArray();
            } catch (IOException e) {
                return null;
            }
        }
        byte[] newKey = new byte[encodedKey.length];
        System.arraycopy(encodedKey, 0, newKey, 0, encodedKey.length);

        return newKey;
    }

    /**
     * Returns the public value, <code>c</code>.
     *
     * @return the public value, <code>c</code>
     */
    public byte[] getC() {
        return this.c.clone();
    }

    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    public KyberParameterSpec getParams() {
        return new KyberParameterSpec(this.p, this.g, this.l);
    }

    /**
     * Parse the encoded cipher text back to the raw cipher text
     *
     * @throws InvalidKeyException
     */
    private void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(this.key);
            byte[] rawArray = in.toByteArray();
            this.c = new byte[rawArray.length - 4];
            System.arraycopy(rawArray, 4, this.c, 0, rawArray.length - 4);
            this.l = this.c.length;
        } catch (IOException e) {
            throw new InvalidKeyException(
                    "Error parsing key encoding: " + e.toString());
        }
    }

    /**
     * Calculates a hash code value for the object. Objects that are equal will
     * also have the same hashcode.
     */
    @Override
    public int hashCode() {
        return Objects.hash(c, p, g);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof KyberCipherText)) {
            return false;
        }

        KyberCipherText other
                = (KyberCipherText) obj;
        KyberParameterSpec otherParams = other.getParams();
        return (((KyberKeyUtil.constantTimeCompare(this.c, other.getC())) == 0)
                && (this.p.compareTo(otherParams.getP()) == 0)
                && (this.g.compareTo(otherParams.getG()) == 0));
    }

    /**
     * Replace the Kyber cipher text to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException if a new object representing this
     * Kyber cipher text could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PUBLIC,
                getAlgorithm(),
                getFormat(),
                getEncoded());
    }
}
