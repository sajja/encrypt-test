package com.test.example.encrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

enum EncryptionAlgo {
    AES_CBC_NOPADDING("AES", "AES/CBC/NoPadding", 0),
    AES_256_CBC_PKCS5("AES", "AES/CBC/PKCS5Padding", 256),
    AES_128_CBC_PKCS5("AES", "AES/CBC/PKCS5Padding", 128);

    private final String type;
    private String value;
    private int bits;

    EncryptionAlgo(String type, String value, int bits) {
        this.value = value;
        this.type = type;
        this.bits = bits;
    }

    public String getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public int getBits() {
        return bits;
    }
}


public class EncryptService {
    /**
     * @param plainText
     * @param hexKey
     * @param hexIV
     * @throws Exception
     */
    public String encrypt(String plainText, EncryptionAlgo algo, String hexKey, String hexIV, boolean padding, boolean salt) throws Exception {
        Cipher cipher = Cipher.getInstance(algo.getValue());

        byte[] key = DatatypeConverter.parseHexBinary(hexKey);

        SecretKeySpec keySpec = new SecretKeySpec(key, 0, algo.getBits() / 8, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(hexIV));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

        String encryptedHexDump = DatatypeConverter.printHexBinary(encrypted);
        String encryptedBase64 = DatatypeConverter.printBase64Binary(encrypted);

        System.out.println("Encrypted hex dump = " + encryptedHexDump);
        System.out.println("");
        System.out.println("Encrypted base64 = " + encryptedBase64);
        return encryptedBase64;
    }


    public String encrypt(String plainText, EncryptionAlgo algo, String hexKey, String hexIV) throws Exception {
        return encrypt(plainText, algo, hexKey, hexIV, false, false);
    }

    public String decrypt(String encryptedData, EncryptionAlgo algo, String hexKey, String hexIV) throws Exception {
        byte[] encryptedBytes = DatatypeConverter.parseBase64Binary(encryptedData);
        byte[] key = DatatypeConverter.parseHexBinary(hexKey);
        SecretKeySpec keySpec = new SecretKeySpec(key, algo.getType());
        Cipher c = Cipher.getInstance(algo.getValue());
        IvParameterSpec ivSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(hexIV));
        c.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decodedValue = c.doFinal(encryptedBytes);
        return new String(decodedValue);
    }
}
