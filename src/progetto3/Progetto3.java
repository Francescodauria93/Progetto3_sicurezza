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
        String[] filesPath = utility.getPathFiles("repoperprogetto3");
        
        for(int i =0;i<filesPath.length;i++){
            System.out.println("ivio:  "+filesPath[i]);
        giovanni.sendDocumentToTSA(filesPath[i], "Tsa1","1");
        ciccio.sendDocumentToTSA(filesPath[i],"Tsa1", "1");
        }

        TSA tsa=new TSA("Tsa1");
        tsa.start();
        
        for(int i =0;i<filesPath.length-4;i++){
            
        giovanni.checkValidity(filesPath[i]);
        
        }
         for(int i =4;i<filesPath.length;i++){
            
        giovanni.checkValidity(filesPath[i]);
        ciccio.checkValidity(filesPath[i]);
        }

    }
    
    
    
}
