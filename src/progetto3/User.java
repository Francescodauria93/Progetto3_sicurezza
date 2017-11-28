/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.*;

/**
 *
 * @author dp.alex
 */
public class User {

    public void sendDocumentToTSA(String pathFile, String id,String idTsa) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        byte[] myID = id.getBytes();
        byte[] fileReaded = utility.loadFile(pathFile);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(fileReaded);
        byte[] hashFileReaded = sha.digest();
        String nameFile = hashFileReaded.toString();
        //creo un ByteArrayOutputStream per concatenare gli array di byte
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(hashFileReaded);
        outputStream.write(myID);
        byte completeDocument[] = outputStream.toByteArray();
        //chiudo lo stram e scrivo l'array di byte appena concatenato
        outputStream.close();
        //creo istanza cifrario RSA
        PublicKey publicTSA = null;
        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "CBC", "PKCS1Padding");
        byte[] DocumentEncrypted = cipherUtility.asimmetricEncode(c, completeDocument, publicTSA);
        //salvo tutto in documento_ID_user.toTsa
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();

        String destEncrypted = s + "/inboxTSA_"+idTsa+"/" + nameFile;
        utility.writeFile(destEncrypted, DocumentEncrypted);

    }

    public void checkValidity(boolean online, String idUser, PublicKey tsaKey, String pathFile) throws IOException, NoSuchAlgorithmException {
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myInboxPath = s + "/inbox_" + idUser+"/";
        String shPath = s + "/folderPublicSuperHashValue";
        byte[] myDoc = null;
        
        myDoc = utility.loadFile(myInboxPath+utility.getNameFromHash(pathFile));
        //intestazione Stringa trasformata in byte[]:  "idMitt/idTsa/#diserie(timeframe)/tipo_di_alg_firma/timestampfoglia i-esima"
    //formato timeStamp: lunghezza intest in byte + intest in byte + hi (foglia i-esima) + sequenzaalbero + sh + sh-1 + firmaTSA
        int size_intest = (int) myDoc[0];
        byte[] intest = new byte[size_intest];
        byte[] hi = null;
        byte[] sequenceMerkle = null;
        byte[] sh = null;
        byte[] preSh = null;
        byte[] sign = null;
        //carico l'intestazione nel suo array di byte 
        intest = Arrays.copyOfRange(myDoc, 1, size_intest + 1);
        //metto i singoli campi dell'intestazione in un array di stringe per poter manipolare i dati
        String[] intestVect = utility.intestToStringArray(intest,5);
        hi=Arrays.copyOfRange(myDoc, size_intest + 1, size_intest +1+ 32);
        sequenceMerkle =Arrays.copyOfRange(myDoc, size_intest + 1+32, size_intest +1+ 32+99);
        sh=Arrays.copyOfRange(myDoc, size_intest +1+ 32+99, size_intest +1+ 32+99+32);
        preSh=Arrays.copyOfRange(myDoc, size_intest +1+ 32+99+32, size_intest +1+ 32+99+32+32);
        sign=preSh=Arrays.copyOfRange(myDoc, size_intest +1+ 32+99+32+32, myDoc.length);
        

    }

    private void checkOffline() {

    }

    private void checkOnline() throws IOException {

        //File dir = new File(myInboxPath);
        //String[] listFileName=dir.list();
        //timeframenumber =Integer.parseInt(listFileName[i].substring(listFileName[i].indexOf("#") + 1, listFileName[i].indexOf("-")));
        //sh=utility.loadFile(shPath + "/superhash" + timeframenumber + ".shv");
        //preSh=utility.loadFile(shPath + "/superhash" + (timeframenumber-1) + ".shv");
    }
    
    
}
