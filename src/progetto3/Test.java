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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author gia
 */
public class Test {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        
        
         Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        s = s + "/wallet/";

        KeyRing c2 = new KeyRing();
        c2.loadKeyRing(s+"ciccio.w","vespa50");
        
        out.println(c2.getPassWeb("google"));
        out.println(c2.getPassWeb("facebook"));
        
        
    }
    
}
