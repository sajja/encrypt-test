package com.test.example.encrypt;

import junit.framework.Assert;
import junit.framework.TestCase;
import sun.misc.BASE64Encoder;
import sun.misc.IOUtils;

import java.io.InputStream;

public class EncryptTest extends TestCase {
    String plainText = "Big bad wold is comming to get red riding hood";
    String cipherText = "b4aU5r0fUycEAcCJxo1uPXsTtE8H9WRvKhV+5SvZjLP1UMawoWFfQx1PQ7kMTL3A";

    String hexKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    String hexIV = "dddddddddddddddddddddddddddddddd";
    EncryptService encryptService = new EncryptService();

    public void testEncryptWith256Key() throws Exception {
        String base64EncodedCipherText = encryptService.encrypt(plainText, EncryptionAlgo.AES_256_CBC_PKCS5, hexKey, hexIV);
        Assert.assertEquals(base64EncodedCipherText, cipherText);
    }

    /**
     * This is a shorter lenght key, but padded with zeros. This is to emulate openssl shorter keys, but higher bit encryption.<br>
     * openssl seem to padd the key. This code is compatible with shorter version of openssl key of ffffffffffffffffffffffffffffffff
     *
     * @throws Exception
     */
    public void testEncryptWith128KeyWithEmtpyBitsAtEnd() throws Exception {
        hexKey = "ffffffffffffffffffffffffffffffff00000000000000000000000000000000";
        cipherText = "ZCLrvbsrkEAdVMuGBZKY5cJnDzMSOZa3arx4kUNAzTG+cB2wAYThSgtbTtlV6sj0";

        String base64EncodedCipherText = encryptService.encrypt(plainText, EncryptionAlgo.AES_256_CBC_PKCS5, hexKey, hexIV);
        Assert.assertEquals(base64EncodedCipherText, cipherText);
    }

    public void testDecrypt() throws Exception {
        Assert.assertEquals(encryptService.decrypt(cipherText, EncryptionAlgo.AES_256_CBC_PKCS5, hexKey, hexIV), plainText);
    }

    public void testOpenSSLCompatibility() throws Exception {
        InputStream is = ClassLoader.getSystemResourceAsStream("openssl_encrypted_file.bin");
        byte[] cipherTextPayload = IOUtils.readFully(is, -1, true);
        Assert.assertEquals(encryptService.decrypt(new BASE64Encoder().encode(cipherTextPayload), EncryptionAlgo.AES_256_CBC_PKCS5, hexKey, hexIV), plainText);
    }

    public void testEncryptionWithLargerKeyThan32Bit() throws Exception {
        hexKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00";
        String base64EncodedCipherText = encryptService.encrypt(plainText, EncryptionAlgo.AES_256_CBC_PKCS5, hexKey, hexIV);
        Assert.assertEquals(base64EncodedCipherText, cipherText);
    }


}