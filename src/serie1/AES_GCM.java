package serie1;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class AES_GCM {

    private GCMParameterSpec spec;
    private Cipher cipher;
    private SecureRandom random;
    private int AES_KEY_SIZE;
    private int GCM_NONCE_LENGTH;
    private int GCM_TAG_LENGTH;
    private byte[] encryptKey;
    private AES_RSA aes_rsa;
    private static String[] certFiles = {"C:\\Users\\Tiago\\Desktop\\SE1\\cert.end.entities\\Alice_1.cer",
            "C:\\Users\\Tiago\\Desktop\\SE1\\cert.CAintermedia\\CA1-int.cer",
            "C:\\Users\\Tiago\\Desktop\\SE1\\trust.anchors\\CA1.cer"};
    private static String keystore = "C:\\Users\\Tiago\\Desktop\\SE1\\pfx\\Alice_1.pfx";

    public AES_GCM(){
        AES_KEY_SIZE = 128;
        GCM_NONCE_LENGTH = 12;
        GCM_TAG_LENGTH = 16;
    }

    public AES_GCM(int aes_key_size_bits, int gcm_nonce_length_bytes, int gcm_tag_length_bytes){
        AES_KEY_SIZE = aes_key_size_bits;
        GCM_NONCE_LENGTH = gcm_nonce_length_bytes;
        GCM_TAG_LENGTH = gcm_tag_length_bytes;
    }

    public byte[] encrypt(String msg) throws Exception{
        random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, random);
        SecretKey key = keyGen.generateKey();

        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        spec = new GCMParameterSpec(GCM_TAG_LENGTH*8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        aes_rsa = new AES_RSA();
        aes_rsa.init(certFiles, keystore );
        encryptKey = aes_rsa.encrypt(key);
        return cipher.doFinal(msg.getBytes());
    }

    public byte[] decrypt(byte[] c, String password) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, aes_rsa.decrypt(encryptKey, password), spec);
        return cipher.doFinal(c);
    }
}
