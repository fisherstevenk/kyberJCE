package com.swiftcryptollc.crypto.provider;

import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;

/**
 * Test the key agreement flow
 *
 * @author Steven K Fisher <fisherstevenk@gmail.com>
 */
public class KeyAgreementTest {

    /**
     * Bob sends public key to Alice
     *
     * Alice generates KyberEncrypted(secret, cipher) from Bob's public Key and
     * her private Key
     *
     * Alice sends Bob the cipher text
     *
     * Bob decrypts the cipher text using his private key to get the secret key
     */
    @Test
    public void testKeyAgreement() {
        try {
            Kyber1024KeyPairGenerator bobKeyGen1024 = new Kyber1024KeyPairGenerator();
            KeyPair bobKeyPair = bobKeyGen1024.generateKeyPair();
            KyberPublicKey bobPublicKey = (KyberPublicKey) bobKeyPair.getPublic();
            KyberPrivateKey bobPrivateKey = (KyberPrivateKey) bobKeyPair.getPrivate();

            Kyber1024KeyPairGenerator aliceKeyGen1024 = new Kyber1024KeyPairGenerator();
            KeyPair aliceKeyPair = aliceKeyGen1024.generateKeyPair();
            KyberPrivateKey alicePrivateKey = (KyberPrivateKey) aliceKeyPair.getPrivate();

            // Bob sends Alice his encoded public Key
            byte[] bobEncodedPublicKey = bobPublicKey.getEncoded();
            // Alice initiates a Key Agreement with Bob
            KyberKeyAgreement aliceKeyAgreement = new KyberKeyAgreement();
            aliceKeyAgreement.engineInit(alicePrivateKey);
            // Generated CipherText and SecretKey from Bob's public Key and Alice's Private Key
            KyberEncrypted aliceCipherSecret = (KyberEncrypted) aliceKeyAgreement.engineDoPhase(new KyberPublicKey(bobEncodedPublicKey), true);
            KyberSecretKey aliceGeneratedSecretKey = aliceCipherSecret.getSecretKey();
            KyberCipherText aliceCipherText = aliceCipherSecret.getCipherText();
            // Send Alice's generated encoded Cipher Text to Bob
            // Bob initializes his own key agreement
            byte[] aliceEncodedCipherText = aliceCipherText.getEncoded();
            KyberKeyAgreement bobKeyAgreement = new KyberKeyAgreement();
            bobKeyAgreement.engineInit(bobPrivateKey);
            // Decrypt the ciphertext back into the secret key
            KyberDecrypted bobKyberDecrypted = (KyberDecrypted) bobKeyAgreement.engineDoPhase(new KyberCipherText(aliceEncodedCipherText), true);
            KyberSecretKey bobGeneratedSecretKey = bobKyberDecrypted.getSecretKey();

            assertTrue(Utilities.constantTimeCompare(aliceGeneratedSecretKey.getS(), bobGeneratedSecretKey.getS()) == 0);
        } catch (Exception ex) {
            fail("Exception occured during the test! [" + ex.getMessage() + "]");
        }
    }
}
