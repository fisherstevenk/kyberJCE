package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.util.KyberKeyUtil;
import java.security.KeyPair;
import java.security.spec.X509EncodedKeySpec;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;

/**
 * Test the X.509 encoding
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public class X509Test {

    /**
     * Test the X.509 encoding
     */
    @Test
    public void testX509() {
        Kyber1024KeyPairGenerator keyGen1024 = new Kyber1024KeyPairGenerator();
        try {
            KeyPair keyPair = keyGen1024.generateKeyPair();
            KyberPublicKey kyberPublicKey = (KyberPublicKey) keyPair.getPublic();
            KyberKeyUtil.validate(kyberPublicKey);

            byte[] publicEncoded = kyberPublicKey.getEncoded();
            KyberKeyFactory responderKeyFac = new KyberKeyFactory();
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicEncoded);
            KyberPublicKey publicKeyFromFactory = (KyberPublicKey) responderKeyFac.engineGeneratePublic(x509KeySpec);
            KyberPublicKey publicKeyFromConstructor = new KyberPublicKey(publicEncoded);
            KyberKeyUtil.validate(publicKeyFromFactory);
            assertTrue(Utilities.constantTimeCompare(publicKeyFromFactory.getY(), publicKeyFromConstructor.getY()) == 0);
            assertTrue(Utilities.constantTimeCompare(kyberPublicKey.getY(), publicKeyFromConstructor.getY()) == 0);
        } catch (Exception ex) {
            fail("Exception occured during X509 testing! [" + ex.getMessage() + "]");
        }
    }
}
