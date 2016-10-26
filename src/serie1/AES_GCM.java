package serie1;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class AES_GCM {

    private SecretKey key;
    private GCMParameterSpec spec;
    private Cipher cipher;
    private SecureRandom random;
    private int AES_KEY_SIZE;
    private int GCM_NONCE_LENGTH;
    private int GCM_TAG_LENGTH;

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

    public void init() throws Exception{
        random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, random);
        key = keyGen.generateKey();

        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        spec = new GCMParameterSpec(GCM_TAG_LENGTH*8, nonce);
    }

    public byte[] encrypt(String msg) throws Exception{
        byte[] input = msg.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(input);
    }

    public byte[] decrypt(byte[] c) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(c);
    }
}
