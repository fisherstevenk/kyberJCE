package com.swiftcryptollc.crypto.provider.kyber;

import java.math.BigInteger;

/**
 * Helper class for various static byte sizes
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public final class KyberParams {

    public final static int paramsN = 256;
    public final static int paramsQ = 3329;
    public final static int paramsQinv = 62209;
    public final static int paramsSymBytes = 32;
    public final static int paramsPolyBytes = 384;
    public final static int paramsETAK512 = 3;
    public final static int paramsETAK768K1024 = 2;
    public final static int paramsPolyvecBytesK512 = 2 * paramsPolyBytes;
    public final static int paramsPolyvecBytesK768 = 3 * paramsPolyBytes;
    public final static int paramsPolyvecBytesK1024 = 4 * paramsPolyBytes;
    public final static int paramsPolyCompressedBytesK512 = 128;
    public final static int paramsPolyCompressedBytesK768 = 128;
    public final static int paramsPolyCompressedBytesK1024 = 160;
    public final static int paramsPolyvecCompressedBytesK512 = 2 * 320;
    public final static int paramsPolyvecCompressedBytesK768 = 3 * 320;
    public final static int paramsPolyvecCompressedBytesK1024 = 4 * 352;
    public final static int paramsIndcpaPublicKeyBytesK512 = paramsPolyvecBytesK512 + paramsSymBytes;
    public final static int paramsIndcpaPublicKeyBytesK768 = paramsPolyvecBytesK768 + paramsSymBytes;
    public final static int paramsIndcpaPublicKeyBytesK1024 = paramsPolyvecBytesK1024 + paramsSymBytes;
    public final static int paramsIndcpaSecretKeyBytesK512 = 2 * paramsPolyBytes;
    public final static int paramsIndcpaSecretKeyBytesK768 = 3 * paramsPolyBytes;
    public final static int paramsIndcpaSecretKeyBytesK1024 = 4 * paramsPolyBytes;

// Kyber512SKBytes is a constant representing the byte length of private keys in Kyber-512
    public final static int Kyber512SKBytes = paramsPolyvecBytesK512 + ((paramsPolyvecBytesK512 + paramsSymBytes) + 2 * paramsSymBytes);

// Kyber768SKBytes is a constant representing the byte length of private keys in Kyber-768
    public final static int Kyber768SKBytes = paramsPolyvecBytesK768 + ((paramsPolyvecBytesK768 + paramsSymBytes) + 2 * paramsSymBytes);

// Kyber1024SKBytes is a constant representing the byte length of private keys in Kyber-1024
    public final static int Kyber1024SKBytes = paramsPolyvecBytesK1024 + ((paramsPolyvecBytesK1024 + paramsSymBytes) + 2 * paramsSymBytes);

// Kyber512PKBytes is a constant representing the byte length of public keys in Kyber-512
    public final static int Kyber512PKBytes = paramsPolyvecBytesK512 + paramsSymBytes;

// Kyber768PKBytes is a constant representing the byte length of public keys in Kyber-768
    public final static int Kyber768PKBytes = paramsPolyvecBytesK768 + paramsSymBytes;

// Kyber1024PKBytes is a constant representing the byte length of public keys in Kyber-1024
    public final static int Kyber1024PKBytes = paramsPolyvecBytesK1024 + paramsSymBytes;

// KyberEncoded512PKBytes is a constant representing the byte length of encoded public keys in Kyber-512
    public final static int KyberEncoded512PKBytes = 967;

// KyberEncoded768PKBytes is a constant representing the byte length of encoded public keys in Kyber-768
    public final static int KyberEncoded768PKBytes = 1351;

// KyberEncoded1024PKBytes is a constant representing the byte length of encoded public keys in Kyber-1024
    public final static int KyberEncoded1024PKBytes = 1735;

// Kyber512CTBytes is a constant representing the byte length of ciphertexts in Kyber-512
    public final static int Kyber512CTBytes = paramsPolyvecCompressedBytesK512 + paramsPolyCompressedBytesK512;

// Kyber768CTBytes is a constant representing the byte length of ciphertexts in Kyber-768
    public final static int Kyber768CTBytes = paramsPolyvecCompressedBytesK768 + paramsPolyCompressedBytesK768;

// Kyber1024CTBytes is a constant representing the byte length of ciphertexts in Kyber-1024
    public final static int Kyber1024CTBytes = paramsPolyvecCompressedBytesK1024 + paramsPolyCompressedBytesK1024;

// KyberEncoded512CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-512
    public final static int KyberEncoded512CTBytes = 935;

// KyberEncoded768CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-768
    public final static int KyberEncoded768CTBytes = 1255;

// KyberEncoded1024CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-1024
    public final static int KyberEncoded1024CTBytes = 1735;

// KyberSSBytes is a constant representing the byte length of shared secrets in Kyber
    public final static int KyberSSBytes = 32;

// KyberEncodedSSBytes is a constant representing the byte length of encoded shared secrets in Kyber
    public final static int KyberEncodedSSBytes = 193;

// Default p value
    public final static BigInteger default_p = new BigInteger("fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17", 16);

// Default g value
    public final static BigInteger default_g = new BigInteger("678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4", 16);
}
