package serie1;

import javax.net.ssl.KeyManagerFactory;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;

public class Certificate_And_Keystore {

    public static PKIXCertPathValidatorResult verifyCertificate(String[] files) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List mylist = new ArrayList();
        FileInputStream in = null;

        in = new FileInputStream(files[0]);
        Certificate c = cf.generateCertificate(in);
        mylist.add(c);

        in = new FileInputStream(files[1]);
        c = cf.generateCertificate(in);
        mylist.add(c);

        CertPath cp = cf.generateCertPath(mylist);

        in = new FileInputStream(files[2]);
        Certificate trust = cf.generateCertificate(in);

        TrustAnchor anchor = new TrustAnchor((X509Certificate) trust, null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        return (PKIXCertPathValidatorResult) cpv.validate(cp, params);
    }

    public static Key get_PriKey_Cert(String path, String password) throws Exception
    {
        KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
        KeyStore keystore = KeyStore.getInstance("PKCS12");

        keystore.load(new FileInputStream(path),password.toCharArray());
        kmf.init(keystore, password.toCharArray());
        Enumeration<String> aliases = keystore.aliases();

        if(aliases.hasMoreElements()) { // get the first aliases, or the first certificate??
            String alias = aliases.nextElement();
            if (keystore.getCertificate(alias).getType().equals("X.509")) {
                Date expDate = ((X509Certificate) keystore.getCertificate(alias)).getNotAfter();
                Date fromDate = ((X509Certificate) keystore.getCertificate(alias)).getNotBefore();
                Date presentDate = new Date();
                if(fromDate.before(presentDate) && expDate.after(presentDate))
                {
                    return keystore.getKey(alias,password.toCharArray());
                }
            }
        }
        throw new InvalidKeyException();
    }

    public static void main(String[] args) {
        String s[] = {"C:\\Users\\Tiago\\Desktop\\SE1\\cert.end.entities\\Alice_1.cer",
                "C:\\Users\\Tiago\\Desktop\\SE1\\cert.CAintermedia\\CA1-int.cer",
                "C:\\Users\\Tiago\\Desktop\\SE1\\trust.anchors\\CA1.cer"};

        try {
            System.out.println(verifyCertificate(s).getPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
