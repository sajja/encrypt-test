package com.test.example.encrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

enum EncryptionAlgo {
    AES_CBC_NOPADDING("AES", "AES/CBC/NoPadding"),
    AES_CBC_PKCS5("AES", "AES/CBC/PKCS5Padding");

    private final String type;
    private String value;

    EncryptionAlgo(String type, String value) {
        this.value = value;
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public String getValue() {
        return value;
    }
}


public class EncryptService {
    /**
     * @param plainText
     * @param hexKey
     * @param hexIV
     * @throws Exception
     */
    public void encrypt(String plainText, EncryptionAlgo algo, String hexKey, String hexIV, boolean padding, boolean salt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] key = DatatypeConverter.parseHexBinary(hexKey);

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(hexIV));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

        String encryptedHexDump = DatatypeConverter.printHexBinary(encrypted);
        String encryptedBase64 = DatatypeConverter.printBase64Binary(encrypted);

        System.out.println("Encrypted hex dump = " + encryptedHexDump);
        System.out.println("");
        System.out.println("Encrypted base64 = " + encryptedBase64);
    }


    public void encrypt(String plainText,EncryptionAlgo algo, String hexKey, String hexIV) throws Exception {
        encrypt(plainText, algo, hexKey, hexIV, false, false);
    }

    public static String decrypt(String encryptedData, EncryptionAlgo algo, String hexKey, String hexIV) throws Exception {
        byte[] encryptedBytes = DatatypeConverter.parseBase64Binary(encryptedData);
        byte[] key = DatatypeConverter.parseHexBinary(hexKey);
        SecretKeySpec keySpec = new SecretKeySpec(key, algo.getType());
        Cipher c = Cipher.getInstance(algo.getValue());
        IvParameterSpec ivSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(hexIV));
        c.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decodedValue = c.doFinal(encryptedBytes);
        return  new String(decodedValue);
    }

    public static void main(String[] args) throws Exception {
        new EncryptService().encrypt("test\n", EncryptionAlgo.AES_CBC_PKCS5, "D41D8CD98F00B2040000000000000000", "03B13BBE886F00E00000000000000000");
        new EncryptService().decrypt("H2714PO496UWMLApd6vl2Q==", EncryptionAlgo.AES_CBC_PKCS5, "D41D8CD98F00B2040000000000000000", "03B13BBE886F00E00000000000000000");
    }
}