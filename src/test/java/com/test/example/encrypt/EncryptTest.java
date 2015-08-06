package com.test.example.encrypt;

import junit.framework.Assert;
import junit.framework.TestCase;
import sun.misc.BASE64Encoder;
import sun.misc.IOUtils;

import java.io.InputStream;

public class EncryptTest extends TestCase {
    String plainText = "Big bad wold is comming to get red riding hood";
    String cipherText = "b4aU5r0fUycEAcCJxo1uPXsTtE8H9WRvKhV+5SvZjLP1UMawoWFfQx1PQ7kMTL3A";

    String hexKey ="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    String hexIV = "dddddddddddddddddddddddddddddddd";
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
