package com.test.example.encrypt;

import junit.framework.Assert;
import junit.framework.TestCase;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.misc.IOUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

/**
 * Created by sajith on 7/20/15.
 */
public class EncryptTest extends TestCase {
    String plainText = "Big bad wold is comming to get red riding hood";
    String cipherText = "ekUp8DIdwYtsw8Or8acSLJkXivqXXDjhqaPZ8JbiC1WVSejlvugA7Mj+RBZtTQQS";

    String hexKey = "D41D8CD98F00B2040000000000000000";
    String hexIV = "03B13BBE886F00E00000000000000000";
    EncryptService encryptService = new EncryptService();

    public void testEncrypt() throws Exception {
        String base64EncodedCipherText = encryptService.encrypt(plainText, EncryptionAlgo.AES_CBC_PKCS5, hexKey, hexIV);
        Assert.assertEquals(base64EncodedCipherText, cipherText);
    }

    public void testDecrypt() throws Exception {
        Assert.assertEquals(encryptService.decrypt(cipherText, EncryptionAlgo.AES_CBC_PKCS5, hexKey, hexIV), plainText);
    }

    public void testOpenSSLCompatibility() throws Exception {
        InputStream is = ClassLoader.getSystemResourceAsStream("openssl_encrypted_file.bin");
        byte[] cipherTextPayload = IOUtils.readFully(is, -1, true);
        Assert.assertEquals(encryptService.decrypt(new BASE64Encoder().encode(cipherTextPayload), EncryptionAlgo.AES_CBC_PKCS5, hexKey, hexIV), plainText);
    }
}
