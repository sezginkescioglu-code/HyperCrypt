import org.hyper.crypt.RsaAlgorithm;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class RsaAlgorithmTest {

    @Test
    public void testRSA_1024Encryption() {
        String message = "Hello, RSA!";
        RsaAlgorithm algorithm = new RsaAlgorithm(RsaAlgorithm.RsaKey.RSA_1024);

        String encrypted = algorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = algorithm.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("RSA_1024 encryption and decryption test passed.");
    }

    @Test
    public void testRSA_2048Encryption() {
        String message = "Hello, RSA!";
        RsaAlgorithm algorithm = new RsaAlgorithm(RsaAlgorithm.RsaKey.RSA_2048);

        String encrypted = algorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = algorithm.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("RSA_2048 encryption and decryption test passed.");
    }

    @Test
    public void testRSA_4096Encryption() {
        String message = "Hello, RSA!";
        RsaAlgorithm algorithm = new RsaAlgorithm(RsaAlgorithm.RsaKey.RSA_4096);

        String encrypted = algorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = algorithm.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("RSA_4096 encryption and decryption test passed.");
    }
}
