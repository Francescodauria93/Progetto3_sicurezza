/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

<<<<<<< HEAD
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
=======
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import progetto3.User;
>>>>>>> a227f67fee91ab66cfd5c2998f34d6cf8bf98072

/**
 *
 * @author dp.alex
 */
public class Progetto3 {

    /**
     * @param args the command line arguments
     */
<<<<<<< HEAD
    public static void main(String[] args) {
    
    System.out.println("Time ricevuto : \n"+fileUtility.getTimeFromServer("Europe/Rome"));
    
=======
    public static void main(String[] args) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, SignatureException {
        
        String userName="gianni";
        String keyPath = Paths.get("src/progetto3").toAbsolutePath().toString()+"/wallet/"+userName+".w";
        String passKR = "dpalex";
        //JFileChooser fileChooser = new JFileChooser();
        User u=new User();
        //Wallet myKR = new Wallet();
        
        //System.out.print(keyPath);
        //myKR.loadWallet(keyPath, passKR);
        String filepath = "/Users/dp.alex/Documents/9.jpg";
        //fileChoice("Scegli il file da marcare:", fileChooser, false);   
        u.sendDocumentToTSA(filepath, "gianni");
    }
    
    public static String fileChoice(String titolo, JFileChooser fileChooser, boolean wallet) {

        if (wallet) {
            Path currentRelativePath = Paths.get("src/progetto3");
            String s = currentRelativePath.toAbsolutePath().toString();
            s = s + "/wallet";
            fileChooser.setCurrentDirectory(new File(s));
        }
        //fileChooser.setCurrentDirectory(new File("));
        //fileChooser.setSelectedFile(new File("README.html"));

        String filename = "";
        fileChooser.setDialogTitle(titolo);
        int result = fileChooser.showOpenDialog(null);

        if (result == JFileChooser.APPROVE_OPTION) {
            filename = fileChooser.getSelectedFile().getPath();

        } else if (result == JFileChooser.CANCEL_OPTION) {
            JOptionPane.showMessageDialog(null, "You selected nothing.");
        } else if (result == JFileChooser.ERROR_OPTION) {
            JOptionPane.showMessageDialog(null, "An error occurred.");
        }

        return filename;
>>>>>>> a227f67fee91ab66cfd5c2998f34d6cf8bf98072
    }
    
}
