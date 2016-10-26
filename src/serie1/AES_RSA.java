package serie1;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class AES_RSA {

    private KeyPair keyPair;
    private Cipher cipher;
    private int RSA_KEY_SIZE;


    public AES_RSA(){
        RSA_KEY_SIZE = 128;
    }

    public void init() throws Exception{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        keyPair = kpg.generateKeyPair();
        cipher = Cipher.getInstance("RSA");
    }

    public byte[] encrypt(SecretKey key) throws Exception{
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(key.getEncoded());
    }

    public SecretKey decrypt(byte[] key) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        SecretKey k = new SecretKeySpec(cipher.doFinal(key), "AES");
        return k;
    }

}
