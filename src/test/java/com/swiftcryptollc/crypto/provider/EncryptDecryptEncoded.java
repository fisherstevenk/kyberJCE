package com.swiftcryptollc.crypto.provider;

import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;

/**
 * Test the to/from byte array functions for the KyberEncrypted and
 * KyberDecrypted classes
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public class EncryptDecryptEncoded {

    @Test
    public void testEncodeDecode() {
        Kyber1024KeyPairGenerator keyGen1024 = new Kyber1024KeyPairGenerator();
        try {
            KeyPair keyPair = keyGen1024.generateKeyPair();
            KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
            keyAgreement.engineInit(keyPair.getPrivate());
            KyberEncrypted cipherSecret = (KyberEncrypted) keyAgreement.engineDoPhase(keyPair.getPublic(), true);
            byte[] encodedArray = cipherSecret.getEncoded();
            KyberEncrypted cipherSecret2 = new KyberEncrypted(encodedArray);

            assertTrue(Utilities.constantTimeCompare(cipherSecret.getSecretKey().getS(), cipherSecret2.getSecretKey().getS()) == 0);
            assertTrue(Utilities.constantTimeCompare(cipherSecret.getCipherText().getC(), cipherSecret2.getCipherText().getC()) == 0);

            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_1024, new KyberCipherText(cipherSecret.getCipherText().getC(), null, null));
            byte[] encodedDecryptedArray = kyberDecrypted.getEncoded();
            KyberDecrypted kyberDecrypted2 = new KyberDecrypted(encodedDecryptedArray);

            assertTrue(Utilities.constantTimeCompare(kyberDecrypted.getSecretKey().getS(), kyberDecrypted2.getSecretKey().getS()) == 0);
            assertTrue(Utilities.constantTimeCompare(kyberDecrypted.getVariant().getBytes(), kyberDecrypted2.getVariant().getBytes()) == 0);

        } catch (Exception ex) {
            fail("Exception occured during testing! [" + ex.getMessage() + "]");
        }
    }
}
