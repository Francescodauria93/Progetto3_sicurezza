/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.FileNotFoundException;
import java.io.IOException;
import static java.lang.System.out;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author gia
 */
public class TestKeyRing {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        s = s + "/wallet";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair userKey = keyPairGenerator.generateKeyPair();
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair userKey2 = keyPairGenerator.generateKeyPair();

        KeyPairGenerator keyPairGenerator2 = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator2.initialize(1024, new SecureRandom());
        KeyPair userKey3 = keyPairGenerator2.generateKeyPair();
        keyPairGenerator2.initialize(2048, new SecureRandom());
        KeyPair userKey4 = keyPairGenerator2.generateKeyPair();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        keyGenerator.init(256, new SecureRandom());
        SecretKey secretKey2 = keyGenerator.generateKey();

        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("DES");
        keyGenerator2.init(56, new SecureRandom());
        SecretKey secretKey3 = keyGenerator2.generateKey();

        KeyRing c2 = new KeyRing();

        c2.addPassWeb("google", "ciao");
        c2.addPassWeb("facebook", "ciao2");
        c2.addKeyPairRSA("azienda", userKey);
        c2.addKeyPairRSA("azienda1", userKey2);
        c2.addKeyPairDSA("azienda", userKey3);
        c2.addKeyPairDSA("azienda1", userKey4);
        c2.addSimmetric("AES", "azienda", secretKey);
        c2.addSimmetric("AES", "azienda1", secretKey2);
        c2.addSimmetric("DES", "azienda", secretKey3);

        c2.SaveKeyRing("vespa50", s, "ciccio");

        KeyRing c3 = new KeyRing();

        c3.loadKeyRing(s + "/ciccio.w", "vespa50");

        out.println(c2.getPassWeb("google").equals(c3.getPassWeb("google")));
        out.println(c2.getPassWeb("facebook").equals(c3.getPassWeb("facebook")));
        out.println(c2.getPrivateDSA("azienda").equals(c3.getPrivateDSA("azienda")));
        out.println(c2.getPrivateDSA("azienda1").equals(c3.getPrivateDSA("azienda1")));
        out.println(c2.getPrivateRSA("azienda").equals(c3.getPrivateRSA("azienda")));
        out.println(c2.getPrivateRSA("azienda1").equals(c3.getPrivateRSA("azienda1")));
        out.println(c2.getPublicDSA("azienda").equals(c3.getPublicDSA("azienda")));
        out.println(c2.getPublicDSA("azienda1").equals(c3.getPublicDSA("azienda1")));
        out.println(c2.getPublicRSA("azienda").equals(c3.getPublicRSA("azienda")));
        out.println(c2.getPublicRSA("azienda1").equals(c3.getPublicRSA("azienda1")));
        out.println(c2.getSimmetric("AES", "azienda").equals(c3.getSimmetric("AES", "azienda")));
        out.println(c2.getSimmetric("AES", "azienda1").equals(c3.getSimmetric("AES", "azienda1")));
        out.println(c2.getSimmetric("DES", "azienda").equals(c3.getSimmetric("DES", "azienda")));

    }

}
