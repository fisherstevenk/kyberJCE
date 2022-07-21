package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.util.KyberKeyUtil;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Tests most of the functionality of the Kyber KEM package
 *
 * This 'test' isn't written as an official test since it takes some time to
 * execute
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public class KemThreadTest {

    /**
     * Random threaded tests looking for any potential threading issues
     *
     * @param args
     */
    @Test
    public void testThreads() {
        int totalErrors = 0;
        List<Thread> testThreads = new ArrayList<>();
        final int numTestsPer = 100;
        final int numThreads = 100;
        long testStartTime = System.currentTimeMillis();
        for (int ctr = 0; ctr < numThreads; ++ctr) {
            final int threadNumber = ctr;
            Thread testThread = new Thread() {
                @Override
                public void run() {
                    this.setName("0");
                    int numErrors = 0;
                    Kyber1024KeyPairGenerator keyGen1024 = new Kyber1024KeyPairGenerator();
                    try {
                        long startTime = System.currentTimeMillis();

                        for (int i = 0; i < numTestsPer; ++i) {
                            try {
                                KeyPair keyPair = keyGen1024.generateKeyPair();
                                KyberPublicKey kyberPublicKey = (KyberPublicKey) keyPair.getPublic();
                                KyberKeyUtil.validate(kyberPublicKey);
                                KyberPrivateKey kyberPrivateKey = (KyberPrivateKey) keyPair.getPrivate();
                                KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
                                keyAgreement.engineInit(kyberPrivateKey);

                                KyberEncrypted cipherSecret = (KyberEncrypted) keyAgreement.engineDoPhase(kyberPublicKey, true);
                                byte[] ciphertext = cipherSecret.getCipherText().getC();
                                byte[] ssA = cipherSecret.getSecretKey().getS();
                                KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_1024,
                                        new KyberCipherText(ciphertext, null, null));
                                KyberSecretKey secretKey = kyberDecrypted.getSecretKey();
                                if (Utilities.constantTimeCompare(ssA, secretKey.getS()) != 0) {
                                    System.out.println("TestThread [" + threadNumber
                                            + "] testKyber iteration [" + i + "]: FAIL");
                                    this.setName(String.valueOf(++numErrors));
                                }

                            } catch (Exception ex) {
                                System.out.println("TestThread [" + threadNumber
                                        + "] Exception occured! [" + ex.getMessage() + "]");
                                ex.printStackTrace();
                                this.setName(String.valueOf(++numErrors));
                            }
                        }
                        long endTime = System.currentTimeMillis();
                        System.out.println("TestThread [" + threadNumber + "] " + numTestsPer
                                + " Random tests took [" + (endTime - startTime) + "] ms");
                    } catch (Exception ex) {
                        System.out.println("Exception occured during testKyber [" + ex.getMessage() + "]");
                        ex.printStackTrace();
                    }
                }
            };
            testThreads.add(testThread);
            testThread.start();
        }

        for (Thread testThread : testThreads) {
            while (testThread.isAlive()) {
                try {
                    Thread.sleep(5);
                } catch (Exception ex) {
                    System.out.println("Exception! [" + ex.getMessage() + "]");
                }
                totalErrors += Integer.parseInt(testThread.getName());
            }
        }
        long testEndTime = System.currentTimeMillis();
        System.out.println((numTestsPer * numThreads)
                + " Total Random tests took approximately [" + (testEndTime - testStartTime) + "] ms");
        System.out.println("testKyber Total errors [" + totalErrors + "]");
    }
}
