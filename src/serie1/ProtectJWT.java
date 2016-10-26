package serie1;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Arrays;

public class ProtectJWT {
    public static void main(String[] args) throws Exception {
        //string test
        AES_GCM aes_gcm = new AES_GCM();
        aes_gcm.init();

        String msg = "this is a string";
        byte[] input = msg.getBytes();

        byte[] cipherText = aes_gcm.encrypt(msg);
        byte[] plainText = aes_gcm.decrypt(cipherText);

        if (Arrays.equals(input, plainText))
            System.out.println("Test Passed: match!");
        System.out.println(new String(cipherText));
        System.out.println(new String(plainText));

        //key test

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        AES_RSA aes_rsa = new AES_RSA();
        aes_rsa.init();

        byte[] cipherKey = aes_rsa.encrypt(key);
        SecretKey key2 = aes_rsa.decrypt(cipherKey);
        if(key.equals(key2))
            System.out.println("Test Passed: match!");
    }
}
