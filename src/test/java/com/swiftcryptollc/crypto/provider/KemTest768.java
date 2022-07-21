package com.swiftcryptollc.crypto.provider;

import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber768CTBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber768PKBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber768SKBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.KyberSSBytes;

/**
 * Simple class for holding data for the 768 tests
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public class KemTest768 {

    public int index = 0;
    public byte[] privateKey = new byte[Kyber768SKBytes];
    public byte[] publicKey = new byte[Kyber768PKBytes];
    public byte[] ciphertext = new byte[Kyber768CTBytes];
    public byte[] sharedSecret = new byte[KyberSSBytes];

    public KemTest768() {

    }
}
