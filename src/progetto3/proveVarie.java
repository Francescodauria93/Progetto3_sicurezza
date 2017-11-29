/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.util.Base64;
import java.io.UnsupportedEncodingException;
import static java.lang.System.out;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 *
 * @author gia
 */
public class proveVarie {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
       String x = "ciao";
       byte[] y = x.getBytes("UTF-8");
       
       String s = new String(y, "US-ASCII");
       
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        sha.update(bytes);
        byte[] shab = sha.digest();
        String shaS = Base64.encode(shab);
        Base64 b = new Base64();

        byte[] shab2 =Base64.decode(shaS);
        
        out.println(shab);
        out.println(shab2);
       
       
      

       
    }
    
}
