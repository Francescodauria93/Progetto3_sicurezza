/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
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
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import progetto3.User;
/**
 *
 * @author dp.alex
 */
public class Progetto3 {
    /**
     * @param args the command line arguments
     */

    public static void main(String[] args) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, SignatureException {
        User giovanni=new User("giovanni");
        User ciccio =new User("ciccio");
        
        KeyRing krGiovanni=new KeyRing();
        krGiovanni.loadKeyRing("/Users/dp.alex/Documents/GitHub/Progetto3_sicurezza/src/progetto3/wallet/giovanni.w", "giovannipass");
        KeyRing krCiccio=new KeyRing();
        krCiccio.loadKeyRing("/Users/dp.alex/Documents/GitHub/Progetto3_sicurezza/src/progetto3/wallet/ciccio.w", "cicciopass");
        KeyRing krTsa=new KeyRing();
        krTsa.loadKeyRing("/Users/dp.alex/Documents/GitHub/Progetto3_sicurezza/src/progetto3/wallet/tsa.w", "tsapass");
        
        String pathFileGiovanni="/Users/dp.alex/Documents/9.jpg";
        String pathFileCiccio="/Users/dp.alex/Documents/frigewallpaper.jpg";

        giovanni.sendDocumentToTSA(pathFileGiovanni,"giovanni", "Tsa1",krGiovanni.getPublicKey("RSA", "tsa_chiave1024_1"));
        ciccio.sendDocumentToTSA(pathFileCiccio, "ciccio", "Tsa1", krCiccio.getPublicKey("RSA", "tsa_chiave1024_1"));
        
        TSA tsa=new TSA(krTsa.getMyPrivateSignature("DSA", "chiave1024_1"));
        tsa.start(krTsa.getMyPrivateAsimmetric("RSA", "chiave1024_1"));
        
        System.out.println(giovanni.checkValidity("Tsa1", krGiovanni.getPublicKey("DSA", "tsa_chiave1024_1")));
        
        //Tsa1.merkelTree("Tsa1", tsaKeyPr,tsaKeyPub);
        
        
        
    }
    
    
    
}
