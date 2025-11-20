import org.hyper.crypt.RabinAlgorithm;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class RabinAlgorithmTest {

    @Test
    public void testRABIN_1024Encryption() {
        String message = "Hello, Rabin!";
        RabinAlgorithm.genKey(RabinAlgorithm.RabinKey.RABIN_1024);

        String encrypted = RabinAlgorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = RabinAlgorithm.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("RABIN_1024 encryption and decryption test passed.");
    }

    @Test
    public void testRABIN_2048Encryption() {
        String message = "Hello, Rabin!";
        RabinAlgorithm.genKey(RabinAlgorithm.RabinKey.RABIN_2048);

        String encrypted = RabinAlgorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = RabinAlgorithm.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("RABIN_2048 encryption and decryption test passed.");
    }

    @Test
    public void testRABIN_4096Encryption() {
        String message = "Hello, Rabin!";
        RabinAlgorithm.genKey(RabinAlgorithm.RabinKey.RABIN_4096);

        String encrypted = RabinAlgorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = RabinAlgorithm.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("RABIN_4096 encryption and decryption test passed.");
    }

}
