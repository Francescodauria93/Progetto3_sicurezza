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
import java.util.ArrayList;
import java.util.List;
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
public class GeneratorKeyRing {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        s = s + "/wallet";
        List<KeyRing> lc = new ArrayList<KeyRing>();
        KeyRing c = new KeyRing();
        KeyRing c2 = new KeyRing();
        KeyPairGenerator gRsa = KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator gDsa = KeyPairGenerator.getInstance("DSA");
        KeyGenerator gAes = KeyGenerator.getInstance("AES");
        KeyGenerator gDes = KeyGenerator.getInstance("DES");
        String[] id = {"ciccio", "fabrizio", "giovanni", "daniele", "annalisa", "giuseppe", "dario", "francesca", "filomena","Tsa1","Tsa2"};

        
        for(int i=0 ; i<11;i++){
            c = new KeyRing();
            for(int  j = 0 ; j<3;j++){
                gRsa.initialize(1024, new SecureRandom());
                c.addKeyPairAsimmetric("RSA", "chiave1024_"+j, gRsa.genKeyPair());
                gRsa.initialize(2048, new SecureRandom());
                c.addKeyPairAsimmetric("RSA", "chiave2048_"+j, gRsa.genKeyPair());
                gDsa.initialize(1024, new SecureRandom());
                c.addKeyPairSignature("DSA", "chiave1024_"+j, gDsa.genKeyPair());
                gDsa.initialize(2048, new SecureRandom());
                c.addKeyPairSignature("DSA", "chiave2048_"+j, gDsa.genKeyPair());
                
                if(id[i].compareTo("tsa")==0){
                    
                gAes.init(128, new SecureRandom());
                c.addSimmetric("AES", "chiave128_"+j, gAes.generateKey());
                gAes.init(256, new SecureRandom());
                c.addSimmetric("AES", "chiave256_"+j, gAes.generateKey());
                gDes.init(56, new SecureRandom());
                c.addSimmetric("DES", "chiave56_"+j, gDes.generateKey());
                
                c.addPassWeb("sito"+j, "pass"+j);
                    
                }
                
                
                
            }
             gAes.init(256, new SecureRandom());
             
             c.SaveKeyRing(id[i]+"pass", s, id[i]);
        }
 
        for (int i = 0; i < 10; i++) {
            c.loadKeyRing(s+"/"+id[i]+".w", id[i]+"pass");
            for(int j = 0 ; j <10; j++){
                if(j!=i){
                    c2.loadKeyRing(s+"/"+id[j]+".w", id[j]+"pass");
                    for(int k=0 ; k < 3 ; k++){
                        c2.addPublicKey("RSA", id[i]+"_chiave1024_"+k, c.getMyPublicAsimmetric("RSA", "chiave1024_"+k));
                        c2.addPublicKey("RSA", id[i]+"_chiave2048_"+k, c.getMyPublicAsimmetric("RSA", "chiave2048_"+k));
                        c2.addPublicKey("DSA", id[i]+"_chiave1024_"+k, c.getMyPublicSignature("DSA", "chiave1024_"+k));
                        c2.addPublicKey("DSA", id[i]+"_chiave2048_"+k, c.getMyPublicSignature("DSA", "chiave2048_"+k));
                       
                    }
                    c2.SaveKeyRing(id[j]+"pass", s, id[j]);
                }
            }
            

        }

      
    }

}
