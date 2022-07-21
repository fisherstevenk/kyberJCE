package com.swiftcryptollc.crypto.provider;

import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber1024CTBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber1024PKBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber1024SKBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.KyberSSBytes;

/**
 * Simple class for holding data for the 1024 tests
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public class KemTest1024 {

    public int index = 0;
    public byte[] privateKey = new byte[Kyber1024SKBytes];
    public byte[] publicKey = new byte[Kyber1024PKBytes];
    public byte[] ciphertext = new byte[Kyber1024CTBytes];
    public byte[] sharedSecret = new byte[KyberSSBytes];

    public KemTest1024() {

    }
}
