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
import progetto3.Journal;

/**
 *
 * @author dp.alex
 */
public class Progetto3 {

    /**
     * @param args the command line arguments
     */

    public static void main(String[] args) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, SignatureException {
        User giovanni = new User("giovanni");

        String[] filesPath = utility.getPathFiles("repoperprogetto3");
        TSA tsa = new TSA("Tsa1");

        for (int i = 0; i < 20; i++) {
            giovanni.sendDocumentToTSA(filesPath[i], "Tsa1", "1");
        }

        tsa.start();
        giovanni.receivesMyMeesages();

        String[] JournalPath = utility.getPathFiles("Public");
        Journal j = new Journal();
        j.load(JournalPath[0]);
        String path = utility.getPathFolder("InboxUsers/");

        String[] log = giovanni.checkValidity(path + "02(giovanni_ven,_dic_1)");
        for (int i = 0; i < log.length; i++) {
            System.out.println(log[i]);
        }

    }

}
