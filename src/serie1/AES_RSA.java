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
    private String certFiles[];
    private String keystoreFiles;


    public AES_RSA(){
        RSA_KEY_SIZE = 128;
    }

    public AES_RSA(int rsa_key_size_bits){
        RSA_KEY_SIZE = rsa_key_size_bits;
    }

    public void init(String certFiles[], String keystoreFiles) throws Exception{
        this.certFiles = certFiles;
        this.keystoreFiles = keystoreFiles;
        cipher = Cipher.getInstance("RSA");
    }

    public byte[] encrypt(SecretKey key) throws Exception{
        cipher.init(Cipher.ENCRYPT_MODE, Certificate_And_Keystore.verifyCertificate(certFiles).getPublicKey());
        return cipher.doFinal(key.getEncoded());
    }

    public SecretKey decrypt(byte[] key,String password) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, Certificate_And_Keystore.get_PriKey_Cert(keystoreFiles, password));
        return new SecretKeySpec(cipher.doFinal(key), "AES");
    }

}
