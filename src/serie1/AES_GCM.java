package serie1;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Created by Tiago on 25/10/2016.
 */
public class AES_GCM {

    public static final int AES_KEY_SIZE = 128; //bits
    public static final int GCM_NONCE_LENGTH = 12;//bytes
    public static final int GCM_TAG_LENGTH = 16;//bytes
    private static SecretKey key;
    private static GCMParameterSpec spec;
    private static Cipher cipher;


    public static void main(String[] args) throws Exception {
        String msg = "isto e uma string";
        byte[] input = msg.getBytes();

        byte[] cipherText = encrypt(msg);
        byte[] plainText = decrypt(cipherText);

        if (Arrays.equals(input, plainText))
            System.out.println("Test Passed: match!");
        System.out.println(new String(cipherText));
        System.out.println(new String(plainText));

    }

    public static byte[] encrypt(String msg) throws Exception{
        byte[] input = msg.getBytes();

        //inicializa random e key generator
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, random);
        key = keyGen.generateKey();

        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        spec = new GCMParameterSpec(GCM_TAG_LENGTH*8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        return cipher.doFinal(input);
    }

    public static byte[] decrypt(byte[] c) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(c);
    }



}
