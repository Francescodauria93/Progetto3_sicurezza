/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;

/**
 *
 * @author dp.alex
 */
public class User {
    
    public void sendDocumentToTSA(String pathFile,String id) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
       
        byte[] myID= id.getBytes();
        byte[] fileReaded=fileUtility.loadFile(pathFile);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(fileReaded);
        byte[] hashFileReaded = sha.digest();
        //creo un ByteArrayOutputStream per concatenare gli array di byte
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(hashFileReaded);
        outputStream.write(myID);
        byte completeDocument[] = outputStream.toByteArray();
        //chiudo lo stram e scrivo l'array di byte appena concatenato
        outputStream.close();
        //creo istanza cifrario RSA
        PublicKey publicTSA = null;
        Cipher c=cipherUtility.getIstanceAsimmetricCipher("RSA","CBC", "PKCS1Padding");
        byte[] DocumentEncrypted=cipherUtility.asimmetricEncode(c, completeDocument, publicTSA);
        //salvo tutto in documento_ID_user.toTsa
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String destEncrypted = s + "/folderWaitingFiles/documento_"+(new String(myID))+".toTsa";
        fileUtility.writeFile(destEncrypted, DocumentEncrypted);
        
    }
}
