package serie1;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Arrays;

public class ProtectJWT {
    public static void main(String[] args) throws Exception {
        //string test
        AES_GCM aes_gcm = new AES_GCM();

        String msg = "this is a string";
        byte[] input = msg.getBytes();

        byte[] cipherText = aes_gcm.encrypt(msg);
        byte[] plainText = aes_gcm.decrypt(cipherText, "");//TODO falta password

        if (Arrays.equals(input, plainText))
            System.out.println("Test Passed: match!");
        System.out.println(new String(cipherText));
        System.out.println(new String(plainText));


    }
}
