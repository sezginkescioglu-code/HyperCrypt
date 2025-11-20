package org.hyper.crypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.IllegalBlockSizeException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;
import de.flexiprovider.pqc.ecc.mceliece.McElieceKeyFactory;
import de.flexiprovider.pqc.ecc.mceliece.McElieceKeyPairGenerator;
import de.flexiprovider.pqc.ecc.mceliece.McEliecePKCS;


public class McElieceAlgorithm {

    private static final String MCLIECE_KEYS_ROOT = Paths.get("src","main","resources").toAbsolutePath().toString(); //"/sdcard/SKSMS_APP/sms/security/keys/mcliece";
    private static final String MCLIECE_PUBLIC= "public.xx";
    private static final String MCLIECE_PRIVATE= "private.xx";

    public static class McElieceKey
    {
        public static final int MCELIECE_1024 = 1024;
        public static final int MCELIECE_2048 = 2048;
        public static final int MCELIECE_4096 = 4096;
    }


    public McElieceAlgorithm(int keyLength) throws Exception {
        initializeMceliece(keyLength);
    }

    private void initializeMceliece(int keyLength) throws Exception {
        if(!checkKeysExist()){
            McElieceKeyPairGenerator kpg = new McElieceKeyPairGenerator();
            kpg.initialize(4096, new SecureRandom());
            java.security.KeyPair pair  = kpg.generateKeyPair();
            SaveKeyPair(MCLIECE_KEYS_ROOT, pair);
        }
    }


    public String encrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        java.security.KeyPair pair  = LoadKeyPair(MCLIECE_KEYS_ROOT, new McElieceKeyFactory());
        PublicKey publicKey = pair.getPublic();
        McEliecePKCS pkcs = new McEliecePKCS();
        pkcs.initEncrypt((Key) publicKey);
        byte[] ciphertextBytes = pkcs.doFinal(message.getBytes());
        BigInteger byteForm = new BigInteger(ciphertextBytes);
        return byteForm.toString();
    }

    public String decyrpt(String message) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException{
        java.security.KeyPair pair  = LoadKeyPair(MCLIECE_KEYS_ROOT, new McElieceKeyFactory());
        PrivateKey privateKey = pair.getPrivate();
        McEliecePKCS pkcs = new McEliecePKCS();
        pkcs.initDecrypt((Key) privateKey);
        BigInteger byteForm = new BigInteger(message);
        byte[] decyrptedBytes = pkcs.doFinal(byteForm.toByteArray());
        String resultString = new String(decyrptedBytes);
        return resultString;
    }


    private static void SaveKeyPair(String path, KeyPair keyPair) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        if(!createKeyFolders()) throw new Exception("");

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());

        FileOutputStream fos = new FileOutputStream(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PUBLIC);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());

        fos = new FileOutputStream(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PRIVATE);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    private static KeyPair LoadKeyPair(String path, McElieceKeyFactory factory) throws IOException, InvalidKeySpecException {

        // Read Public Key.
        File filePublicKey = new File(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PUBLIC);
        FileInputStream fis = new FileInputStream(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PUBLIC);
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PRIVATE);
        fis = new FileInputStream(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PRIVATE);
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        de.flexiprovider.pki.X509EncodedKeySpec publicKeySpec = new de.flexiprovider.pki.X509EncodedKeySpec(encodedPublicKey);

        PublicKey publicKey = factory.generatePublic((KeySpec) publicKeySpec);

        de.flexiprovider.pki.PKCS8EncodedKeySpec privateKeySpec = new de.flexiprovider.pki.PKCS8EncodedKeySpec(encodedPrivateKey);

        PrivateKey privateKey = factory.generatePrivate((KeySpec) privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }


    private static boolean createKeyFolders(){
        boolean success = false;
        File keyFolderPath = new File(MCLIECE_KEYS_ROOT);
        if(!keyFolderPath.exists())
            success= keyFolderPath.mkdirs();
        success = true;
        return success;
    }

    private static boolean checkKeysExist(){
        File privateKey = new File(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PRIVATE);
        File publicKey = new File(MCLIECE_KEYS_ROOT + File.separator + MCLIECE_PUBLIC);

        return privateKey.exists() & publicKey.exists();
    }
}
