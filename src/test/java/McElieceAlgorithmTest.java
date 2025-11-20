import org.hyper.crypt.McElieceAlgorithm;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class McElieceAlgorithmTest {

    @Test
    public void testMCELIECE_1024Encryption() throws Exception {
        String message = "Hello, McEliece!";
        McElieceAlgorithm mcElieceAlgorithm = new McElieceAlgorithm(McElieceAlgorithm.McElieceKey.MCELIECE_1024);

        String encrypted = mcElieceAlgorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = mcElieceAlgorithm.decyrpt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("MCELIECE_1024 encryption and decryption test passed.");
    }

    @Test
    public void testMCELIECE_2048Encryption() throws Exception {
        String message = "Hello, McEliece!";
        McElieceAlgorithm mcElieceAlgorithm = new McElieceAlgorithm(McElieceAlgorithm.McElieceKey.MCELIECE_2048);

        String encrypted = mcElieceAlgorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = mcElieceAlgorithm.decyrpt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("MCELIECE_2048 encryption and decryption test passed.");
    }

    @Test
    public void testMCELIECE_4096Encryption() throws Exception {
        String message = "Hello, McEliece!";
        McElieceAlgorithm mcElieceAlgorithm = new McElieceAlgorithm(McElieceAlgorithm.McElieceKey.MCELIECE_4096);

        String encrypted = mcElieceAlgorithm.encrypt(message);
        System.out.println("Encrypted: " + encrypted);
        assertNotNull(encrypted);

        String decrypted = mcElieceAlgorithm.decyrpt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        assertNotNull(decrypted);
        assertEquals(message, decrypted);
        System.out.println("MCELIECE_4096 encryption and decryption test passed.");
    }

}
