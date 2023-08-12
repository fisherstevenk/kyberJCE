package com.swiftcryptollc.crypto.provider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;

/**
 * Tests most of the functionality of the Kyber KEM package
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public class KemTest {

    public KemTest512 kt512 = new KemTest512();
    public KemTest768 kt768 = new KemTest768();
    public KemTest1024 kt1024 = new KemTest1024();

    /**
     * Test the system using the data files
     */
    @Test
    public void testFileData() {
        String[] rsps = new String[]{
            "PQCkemKAT_1632.rsp",
            "PQCkemKAT_2400.rsp",
            "PQCkemKAT_3168.rsp"};
        int fileIndex = 0;
        for (String rsp : rsps) {
            InputStream inputStream = null;
            InputStreamReader inputStreamReader = null;
            try {
                inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("assets/" + rsp);
                inputStreamReader = new InputStreamReader(inputStream);
                System.out.println("Processing " + rsp);
                BufferedReader br = new BufferedReader(inputStreamReader);
                String line = null;
                int count = 0;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.indexOf("=") > -1) {
                        String[] split = line.split("=");
                        String key = split[0].trim();
                        String value = split[1].trim();
                        if (key.equals("count")) {
                            count = Integer.parseInt(value);
                            if (count > 0) {
                                switch (fileIndex) {
                                    case 0:
                                        testVectors512(kt512);
                                        testConversion512(kt512);
                                        testSelf512(kt512.index);
                                        break;
                                    case 1:
                                        testVectors768(kt768);
                                        testConversion768(kt768);
                                        testSelf768(kt768.index);
                                        break;
                                    default:
                                        testVectors1024(kt1024);
                                        testConversion1024(kt1024);
                                        testSelf1024(kt1024.index);
                                        break;
                                }
                            }
                            kt512 = new KemTest512();
                            kt512.index = count;
                            kt768 = new KemTest768();
                            kt768.index = count;
                            kt1024 = new KemTest1024();
                            kt1024.index = count;
                        } else if (key.equals("pk")) {
                            switch (fileIndex) {
                                case 0:
                                    kt512.publicKey = toByteArray(value);
                                    break;
                                case 1:
                                    kt768.publicKey = toByteArray(value);
                                    break;
                                case 2:
                                    kt1024.publicKey = toByteArray(value);
                                    break;
                            }

                        } else if (key.equals("sk")) {
                            switch (fileIndex) {
                                case 0:
                                    kt512.privateKey = toByteArray(value);
                                    break;
                                case 1:
                                    kt768.privateKey = toByteArray(value);
                                    break;
                                case 2:
                                    kt1024.privateKey = toByteArray(value);
                                    break;
                            }

                        } else if (key.equals("ct")) {
                            switch (fileIndex) {
                                case 0:
                                    kt512.ciphertext = toByteArray(value);
                                    break;
                                case 1:
                                    kt768.ciphertext = toByteArray(value);
                                    break;
                                case 2:
                                    kt1024.ciphertext = toByteArray(value);
                                    break;
                            }

                        } else if (key.equals("ss")) {
                            switch (fileIndex) {
                                case 0:
                                    kt512.sharedSecret = toByteArray(value);
                                    break;
                                case 1:
                                    kt768.sharedSecret = toByteArray(value);
                                    break;
                                case 2:
                                    kt1024.sharedSecret = toByteArray(value);
                                    break;
                            }

                        }

                    }
                }

            } catch (Exception ex) {
                ex.printStackTrace();
                fail("Exception occured during the test! [" + ex.getMessage() + "]");
            } finally {
                try {
                    if (inputStreamReader != null) {
                        inputStreamReader.close();
                    }
                    if (inputStream != null) {
                        inputStream.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            /**
             * Process the last vector
             */
            switch (fileIndex) {
                case 0:
                    testVectors512(kt512);
                    testConversion512(kt512);
                    testSelf512(kt512.index);
                    break;
                case 1:
                    testVectors768(kt768);
                    testConversion768(kt768);
                    testSelf768(kt768.index);
                    break;
                default:
                    testVectors1024(kt1024);
                    testConversion1024(kt1024);
                    testSelf1024(kt1024.index);
                    break;
            }
            ++fileIndex;
        }
    }

    /**
     * Verifies that the private key is stored properly and that it is encoded
     * and decoded properly
     *
     * @param test
     */
    public void testConversion512(KemTest512 test) {
        try {
            KyberPrivateKey privateKey = new KyberPrivateKey(test.privateKey, null, null);
            byte[] convertedX = privateKey.getX();
            assertTrue((Utilities.constantTimeCompare(test.privateKey, convertedX) == 0),
                    "512 Private Key Conversion error! [" + test.index + "]");

            KyberPrivateKey privateKey2 = new KyberPrivateKey(privateKey.getEncoded());
            byte[] convertedX2 = privateKey2.getX();
            assertTrue((Utilities.constantTimeCompare(test.privateKey, convertedX2) == 0),
                    "512 Private Key 2 Conversion error! [" + test.index + "]");

            KyberPublicKey publicKey = new KyberPublicKey(test.publicKey, null, null);
            byte[] convertedY = publicKey.getY();
            assertTrue((Utilities.constantTimeCompare(test.publicKey, convertedY) == 0),
                    "512 Public Key Conversion error! [" + test.index + "]");

            KyberPublicKey publicKey2 = new KyberPublicKey(publicKey.getEncoded());
            byte[] convertedY2 = publicKey2.getY();
            assertTrue((Utilities.constantTimeCompare(test.publicKey, convertedY2) == 0),
                    "512 Public Key 2 Conversion error! [" + test.index + "]");

            KyberSecretKey secretKey = new KyberSecretKey(test.sharedSecret, null, null);
            byte[] convertedS = secretKey.getS();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, convertedS) == 0),
                    "512 Secret Key Conversion error! [" + test.index + "]");

            KyberSecretKey secretKey2 = new KyberSecretKey(secretKey.getEncoded());
            byte[] convertedS2 = secretKey2.getS();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, convertedS2) == 0),
                    "512 Secret Key 2 Conversion error! [" + test.index + "]");
        } catch (Exception ex) {
            fail("Exception occured during testConversion512 [" + test.index + "] [" + ex.getMessage() + "]");
        }
    }

    /**
     * Verifies that the private key is stored properly and that it is encoded
     * and decoded properly
     *
     * @param test
     */
    public void testConversion768(KemTest768 test) {
        try {
            KyberPrivateKey privateKey = new KyberPrivateKey(test.privateKey, null, null);
            byte[] convertedX = privateKey.getX();
            assertTrue((Utilities.constantTimeCompare(test.privateKey, convertedX) == 0),
                    "768 Private Key Conversion error! [" + test.index + "]");

            KyberPrivateKey privateKey2 = new KyberPrivateKey(privateKey.getEncoded());
            byte[] convertedX2 = privateKey2.getX();
            assertTrue((Utilities.constantTimeCompare(test.privateKey, convertedX2) == 0),
                    "768 Private Key 2 Conversion error! [" + test.index + "]");

            KyberPublicKey publicKey = new KyberPublicKey(test.publicKey, null, null);
            byte[] convertedY = publicKey.getY();
            assertTrue((Utilities.constantTimeCompare(test.publicKey, convertedY) == 0),
                    "768 Public Key Conversion error! [" + test.index + "]");

            KyberPublicKey publicKey2 = new KyberPublicKey(publicKey.getEncoded());
            byte[] convertedY2 = publicKey2.getY();
            assertTrue((Utilities.constantTimeCompare(test.publicKey, convertedY2) == 0),
                    "768 Public Key 2 Conversion error! [" + test.index + "]");

            KyberSecretKey secretKey = new KyberSecretKey(test.sharedSecret, null, null);
            byte[] convertedS = secretKey.getS();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, convertedS) == 0),
                    "768 Secret Key Conversion error! [" + test.index + "]");

            KyberSecretKey secretKey2 = new KyberSecretKey(secretKey.getEncoded());
            byte[] convertedS2 = secretKey2.getS();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, convertedS2) == 0),
                    "768 Secret Key 2 Conversion error! [" + test.index + "]");
        } catch (Exception ex) {
            fail("Exception occured during testConversion768 [" + test.index + "] [" + ex.getMessage() + "]");
        }
    }

    /**
     * Verifies that the private key is stored properly and that it is encoded
     * and decoded properly
     *
     * @param test
     */
    public void testConversion1024(KemTest1024 test) {
        try {
            KyberPrivateKey privateKey = new KyberPrivateKey(test.privateKey, null, null);
            byte[] convertedX = privateKey.getX();
            assertTrue((Utilities.constantTimeCompare(test.privateKey, convertedX) == 0),
                    "1024 Private Key Conversion error! [" + test.index + "]");

            KyberPrivateKey privateKey2 = new KyberPrivateKey(privateKey.getEncoded());
            byte[] convertedX2 = privateKey2.getX();
            assertTrue((Utilities.constantTimeCompare(test.privateKey, convertedX2) == 0),
                    "1024 Private Key 2 Conversion error! [" + test.index + "]");

            KyberPublicKey publicKey = new KyberPublicKey(test.publicKey, null, null);
            byte[] convertedY = publicKey.getY();
            assertTrue((Utilities.constantTimeCompare(test.publicKey, convertedY) == 0),
                    "1024 Public Key Conversion error! [" + test.index + "]");

            KyberPublicKey publicKey2 = new KyberPublicKey(publicKey.getEncoded());
            byte[] convertedY2 = publicKey2.getY();
            assertTrue((Utilities.constantTimeCompare(test.publicKey, convertedY2) == 0),
                    "1024 Public Key 2 Conversion error! [" + test.index + "]");

            KyberSecretKey secretKey = new KyberSecretKey(test.sharedSecret, null, null);
            byte[] convertedS = secretKey.getS();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, convertedS) == 0),
                    "1024 Secret Key Conversion error! [" + test.index + "]");

            KyberSecretKey secretKey2 = new KyberSecretKey(secretKey.getEncoded());
            byte[] convertedS2 = secretKey2.getS();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, convertedS2) == 0),
                    "1024 Secret Key 2 Conversion error! [" + test.index + "]");
        } catch (Exception ex) {
            fail("Exception occured during testConversion1024 [" + test.index + "] [" + ex.getMessage() + "]");
        }
    }

    /**
     * Test the pre-built 512 data from file PQCkemKAT_1632.rsp
     *
     * @param test
     */
    public void testVectors512(KemTest512 test) {
        KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
        try {
            KyberPrivateKey privateKey = new KyberPrivateKey(test.privateKey, null, null);
            keyAgreement.engineInit(privateKey);
            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_512, new KyberCipherText(test.ciphertext, null, null));
            KyberSecretKey secretKey = kyberDecrypted.getSecretKey();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, secretKey.getS()) == 0), "TestVectors512 test vector [" + test.index + "]: FAIL");
        } catch (Exception ex) {
            fail("Exception occured during testVectors512 [" + test.index + "] [" + ex.getMessage() + "]");
        }
    }

    /**
     * Test the pre-built 768 data from file PQCkemKAT_2400.rsp
     *
     * @param test
     */
    public void testVectors768(KemTest768 test) {
        KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
        try {
            KyberPrivateKey privateKey = new KyberPrivateKey(test.privateKey, null, null);
            keyAgreement.engineInit(privateKey);
            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_768, new KyberCipherText(test.ciphertext, null, null));
            KyberSecretKey secretKey = kyberDecrypted.getSecretKey();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, secretKey.getS()) == 0), "TestVectors768 test vector [" + test.index + "]: FAIL");
        } catch (Exception ex) {
            fail("Exception occured during testVectors768 [" + test.index + "] [" + ex.getMessage() + "]");
        }
    }

    /**
     * Test the pre-built 1024 data from file PQCkemKAT_3168.rsp
     *
     * @param test
     */
    public void testVectors1024(KemTest1024 test) {
        KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
        try {
            KyberPrivateKey privateKey = new KyberPrivateKey(test.privateKey, null, null);
            keyAgreement.engineInit(privateKey);
            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_1024, new KyberCipherText(test.ciphertext, null, null));
            KyberSecretKey secretKey = kyberDecrypted.getSecretKey();
            assertTrue((Utilities.constantTimeCompare(test.sharedSecret, secretKey.getS()) == 0), "TestVectors1024 test vector [" + test.index + "]: FAIL");
        } catch (Exception ex) {
            fail("Exception occured during testVectors1024 [" + test.index + "] [" + ex.getMessage() + "]");
        }
    }

    /**
     * Generate a new 512 key pair, verify the same secret key is created
     *
     * @params i
     */
    public void testSelf512(int i) {
        Kyber512KeyPairGenerator keyGen512 = new Kyber512KeyPairGenerator();
        KeyPair keyPair = keyGen512.generateKeyPair();
        KyberPublicKey kyberPublicKey = (KyberPublicKey) keyPair.getPublic();
        KyberPrivateKey kyberPrivateKey = (KyberPrivateKey) keyPair.getPrivate();
        try {
            KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
            keyAgreement.engineInit(kyberPrivateKey);
            KyberEncrypted cipherSecret = (KyberEncrypted) keyAgreement.engineDoPhase(kyberPublicKey, true);
            byte[] ciphertext = cipherSecret.getCipherText().getC();
            byte[] ssA = cipherSecret.getSecretKey().getS();
            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_512, new KyberCipherText(ciphertext, null, null));
            KyberSecretKey secretKey = kyberDecrypted.getSecretKey();
            assertTrue((Utilities.constantTimeCompare(ssA, secretKey.getS()) == 0), "TestSelf512 iteration [" + i + "]: FAIL");
        } catch (Exception ex) {
            fail("TestSelf512 iteration [" + i + "]: FAIL: Exception occured! [" + ex.getMessage() + "]");
        }
    }

    /**
     * Generate a new 768 key pair, verify the same secret key is created
     *
     * @params i
     */
    public void testSelf768(int i) {
        Kyber768KeyPairGenerator keyGen768 = new Kyber768KeyPairGenerator();
        KeyPair keyPair = keyGen768.generateKeyPair();
        KyberPublicKey kyberPublicKey = (KyberPublicKey) keyPair.getPublic();
        KyberPrivateKey kyberPrivateKey = (KyberPrivateKey) keyPair.getPrivate();
        try {
            KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
            keyAgreement.engineInit(kyberPrivateKey);
            KyberEncrypted cipherSecret = (KyberEncrypted) keyAgreement.engineDoPhase(kyberPublicKey, true);
            byte[] ciphertext = cipherSecret.getCipherText().getC();
            byte[] ssA = cipherSecret.getSecretKey().getS();
            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_768, new KyberCipherText(ciphertext, null, null));
            KyberSecretKey secretKey = kyberDecrypted.getSecretKey();
            assertTrue((Utilities.constantTimeCompare(ssA, secretKey.getS()) == 0), "TestSelf768 iteration [" + i + "]: FAIL");
        } catch (Exception ex) {
            fail("TestSelf768 iteration [" + i + "]: FAIL: Exception occured! [" + ex.getMessage() + "]");
        }
    }

    /**
     * Generate a new 1024 key pair, verify the same secret key is created
     *
     * @params i
     */
    public void testSelf1024(int i) {
        Kyber1024KeyPairGenerator keyGen1024 = new Kyber1024KeyPairGenerator();
        KeyPair keyPair = keyGen1024.generateKeyPair();
        KyberPublicKey kyberPublicKey = (KyberPublicKey) keyPair.getPublic();
        KyberPrivateKey kyberPrivateKey = (KyberPrivateKey) keyPair.getPrivate();
        try {
            KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
            keyAgreement.engineInit(kyberPrivateKey);
            KyberEncrypted cipherSecret = (KyberEncrypted) keyAgreement.engineDoPhase(kyberPublicKey, true);
            byte[] ciphertext = cipherSecret.getCipherText().getC();
            byte[] ssA = cipherSecret.getSecretKey().getS();
            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_1024, new KyberCipherText(ciphertext, null, null));
            KyberSecretKey secretKey = kyberDecrypted.getSecretKey();
            assertTrue((Utilities.constantTimeCompare(ssA, secretKey.getS()) == 0), "TestSelf1024 iteration [" + i + "]: FAIL");
        } catch (Exception ex) {
            fail("TestSelf1024 iteration [" + i + "]: FAIL: Exception occured! [" + ex.getMessage() + "]");
        }
    }

    /**
     * Convert a string to a byte array
     *
     * @param hexString
     * @return
     */
    public byte[] toByteArray(String hexString) {
        int numChars = hexString.length();
        byte[] bytes = new byte[numChars / 2];
        int hexIndex = 0;
        for (int i = 0; i < hexString.length(); i += 2) {
            int initial = Integer.parseInt(hexString.substring(i, i + 2), 16);
            bytes[hexIndex++] = (byte) initial;
        }
        return bytes;
    }
}
