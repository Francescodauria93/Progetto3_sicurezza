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
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;

/**
 *
 * @author dp.alex
 */
public class User {
    
    private String myID;

    public User(String myID) {
        this.myID = myID;
    }
    
    

    public void sendDocumentToTSA(String pathFile, String id, String idTsa,PublicKey publicTSA) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        byte[] myID = id.getBytes();
        byte[] fileReaded = utility.loadFile(pathFile);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(fileReaded);
        byte[] hashFileReaded = sha.digest();
        String nameFile = utility.nameFile(pathFile);
        //creo un ByteArrayOutputStream per concatenare gli array di byte
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(hashFileReaded);
        outputStream.write(myID);
        byte completeDocument[] = outputStream.toByteArray();
        //chiudo lo stram e scrivo l'array di byte appena concatenato
        outputStream.close();
        //creo istanza cifrario RSA
        
        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "ECB", "PKCS1Padding");
        byte[] DocumentEncrypted = cipherUtility.asimmetricEncode(c, completeDocument, publicTSA);
        //salvo tutto in documento_ID_user.toTsa
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String destEncrypted = s + "/inboxTSA_" + idTsa + "/" + nameFile;
        utility.writeFile(destEncrypted, DocumentEncrypted);

    }

    public boolean checkValidity(String idTsa, PublicKey tsaKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        System.out.println("*****");
        Path currentRelativePath = Paths.get("src/progetto3"); //cambiare solo il salvataggio----
        String s = currentRelativePath.toAbsolutePath().toString();
        String myInboxPath = s + "/readyTSA_" + idTsa + "/";
        boolean check = false;
        byte[] myDoc = utility.loadFile(myInboxPath + this.myID +".mt");
        System.out.println(myDoc.length);
        //intestazione Stringa trasformata in byte[]:  "idMitt/idTsa/#diserie(timeframe)/tipo_di_alg_firma/timestampfoglia i-esima"
        //formato timeStamp: lunghezza intest in byte + intest in byte + hi (foglia i-esima) + sequenzaalbero + sh + sh-1 + firmaTSA
        int size_intest = (int) myDoc[0];
        byte[] intest = Arrays.copyOfRange(myDoc, 1, size_intest + 1);
         System.out.println(intest.length);
        String[] intestVect = utility.intestToStringArray(intest, 5);
    
        byte[] hi = Arrays.copyOfRange(myDoc, size_intest + 1, size_intest + 1 + 32);
         System.out.println(hi.length);
        
        byte[] sequenceMerkle = Arrays.copyOfRange(myDoc, size_intest + 1 + 32, size_intest + 1 + 32 + 99);
        System.out.println(sequenceMerkle.length);
        byte[] sh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99, size_intest + 1 + 32 + 99 + 32);
        System.out.println(sh.length);
        byte[] preSh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32, size_intest + 1 + 32 + 99 + 32 + 32);
        System.out.println(preSh.length);
        byte[] sign = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32 + 32, myDoc.length);
        
        System.out.println(sign.length + " "+ (size_intest + 1 + 32 + 99 + 32 + 32) +" - "+myDoc.length);
        byte[] arrayToVerify = Arrays.copyOfRange(myDoc, 0, myDoc.length-sign.length);
        System.out.println("*****");
        byte[] rootHash = this.constructRoot(hi, sequenceMerkle);
        System.out.println("root -> "+Base64.getEncoder().encodeToString(rootHash));
        System.out.println("preSH -> "+Base64.getEncoder().encodeToString(preSh));
        System.out.println("SH - > "+Base64.getEncoder().encodeToString(sh));
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        sha.update(utility.concatByte(preSh, rootHash));
        byte[] shC=sha.digest();
        if ((utility.verifySign(arrayToVerify, sign, tsaKey, intestVect[3])) ) {
            System.out.println("firma buona");
          System.out.println("1 : "+Base64.getEncoder().encodeToString(shC)+"\n"+"2 : "+Base64.getEncoder().encodeToString(sh));
            if(Arrays.equals(sh, shC)){
                System.out.println("root buona");
                check=true; //sistemare con array copy
            }
            
        }
        return check;

    }

    private byte[] constructRoot(byte[] hi, byte[] sequence) throws IOException, NoSuchAlgorithmException {
        
        System.out.println("hi ->" +Base64.getEncoder().encodeToString(hi));
        byte firstFusion = sequence[0];
        byte[] brotherLeaf = Arrays.copyOfRange(sequence, 1, 33);
        System.out.println("1 -- " + firstFusion + " -> "+Base64.getEncoder().encodeToString(brotherLeaf));
        byte secondFusion = sequence[33];
        byte[] firstBrother = Arrays.copyOfRange(sequence, 34, 66);
         System.out.println("2 -- " + secondFusion+ " -> "+Base64.getEncoder().encodeToString(firstBrother));
        byte thirdFusion = sequence[66];
        byte[] lastBrother = Arrays.copyOfRange(sequence, 67, sequence.length);
        System.out.println("3 -- " + thirdFusion+ " -> "+Base64.getEncoder().encodeToString(lastBrother));
        byte[] root = null;
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA

        if (firstFusion == 0) {
            sha.update(utility.concatByte(hi, brotherLeaf));
            root = sha.digest();
        } else {
            sha.update(utility.concatByte(brotherLeaf, hi));
            root = sha.digest();
        }
        if (secondFusion == 0) {
            sha.update(utility.concatByte(root, firstBrother));
            root = sha.digest();
        } else {
            sha.update(utility.concatByte(firstBrother, root));
            root = sha.digest();
        }
        if (thirdFusion == 0) {
            sha.update(utility.concatByte(root, lastBrother));
            root = sha.digest();
        } else {
            sha.update(utility.concatByte(lastBrother, root)); //ok solo un pò il codice
            root = sha.digest();   
        }
        return root;
    }

    private boolean checkChain() throws IOException {
        return true;
    }

}
