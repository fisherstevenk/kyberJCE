package com.swiftcryptollc.crypto.provider;

import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber512PKBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber512SKBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.Kyber768CTBytes;
import static com.swiftcryptollc.crypto.provider.kyber.KyberParams.KyberSSBytes;

/**
 * Simple class for holding data for the 512 tests
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public class KemTest512 {

    public int index = 0;
    public byte[] privateKey = new byte[Kyber512SKBytes];
    public byte[] publicKey = new byte[Kyber512PKBytes];
    public byte[] ciphertext = new byte[Kyber768CTBytes];
    public byte[] sharedSecret = new byte[KyberSSBytes];

    public KemTest512() {

    }
}
