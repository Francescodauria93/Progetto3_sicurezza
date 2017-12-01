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
import java.nio.file.Files;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.*;
import progetto3.KeyRing;
/**
 *
 * @author dp.alex
 */
public class User {
    
    private String myID;
    private String indexRsaUsedbyMe;
    private String indexDsaUsedbyTsa="1";
    private String tsaID;
    private KeyRing myKR;
    private Map<String, String> mappingNameFromOriginal = new HashMap<String, String>();
    
    public User(String myID) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        this.myID = myID;
        this.myKR = new KeyRing();
        String kRFolder = utility.getPathFolder("wallet/");
        this.myKR.loadKeyRing(kRFolder+this.myID+".w", this.myID+"pass");

    }

    public void sendDocumentToTSA(String pathFile, String idTsa,String i) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
     
        this.indexRsaUsedbyMe=i;
        this.tsaID=idTsa;
        //preparo byte da inviare
        byte[] myID = this.myID.getBytes();
        byte[] hashFileReaded =utility.toHash256(utility.loadFile(pathFile));
       
        //creo un ByteArrayOutputStream per concatenare gli array di byte
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(hashFileReaded);
        outputStream.write(myID);
        byte completeDocument[] = outputStream.toByteArray();
        
        //chiudo lo stram e scrivo l'array di byte appena concatenato
        outputStream.close();
        //creo istanza cifrario RSA
        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "ECB", "PKCS1Padding");
        byte[] DocumentEncrypted = cipherUtility.asimmetricEncode(c, completeDocument, this.myKR.getPublicKey("RSA",this.tsaID+ "_chiave1024_"+this.indexDsaUsedbyTsa));
        //salvo tutto in documento_ID_user.toTsa
        String destFolder = utility.getPathFolder("inboxTSA_" + idTsa + "/");
        String indexName=utility.getIndexNameToSave(this.myID , utility.getPathFolder("inboxTSA_" + idTsa + "/"));
        this.mappingNameFromOriginal.put(pathFile,this.myID+"-"+indexName);
        utility.writeFile(destFolder+this.myID+"-"+indexName, DocumentEncrypted);

    }

    public String[] checkValidity(String pathToVerify) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException {
  
        String pathReadyTsa=utility.getPathFolder("readyTSA_" + this.tsaID + "/");
        String destFolder = utility.getPathFolder("inboxUsers/");

        byte[] myDoc = utility.loadFile(utility.getPathFolder("readyTSA_" + this.tsaID + "/")+this.mappingNameFromOriginal.get(pathToVerify));
        int size_intest = (int) myDoc[0];
        byte[] intest = Arrays.copyOfRange(myDoc, 1, size_intest + 1);
        String[] intestVect = utility.intestToStringArray(intest, 5);
        byte[] hi = Arrays.copyOfRange(myDoc, size_intest + 1, size_intest + 1 + 32);
        byte[] sequenceMerkle = Arrays.copyOfRange(myDoc, size_intest + 1 + 32, size_intest + 1 + 32 + 99);
        byte[] sh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99, size_intest + 1 + 32 + 99 + 32);
        byte[] preSh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32, size_intest + 1 + 32 + 99 + 32 + 32);
        byte[] sign = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32 + 32, myDoc.length);
        byte[] arrayToVerify = Arrays.copyOfRange(myDoc, 0, myDoc.length-sign.length);
        byte[] myHi = utility.toHash256(utility.concatByte(utility.toHash256(utility.loadFile(pathToVerify)),intestVect[4].getBytes()));
        byte[] rootHash = this.constructRoot(hi, sequenceMerkle);
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        sha.update(utility.concatByte(preSh, rootHash));
        byte[] shC=sha.digest();
        if (Arrays.equals(myHi,hi) && (utility.verifySign(arrayToVerify, sign, this.myKR.getPublicKey("DSA", this.tsaID+ "_chiave1024_"+this.indexDsaUsedbyTsa), intestVect[3])) && Arrays.equals(sh, shC)) {
               utility.writeFile(destFolder+utility.nameFile(pathToVerify)+"_"+this.myID+".valid_mt", myDoc);  
            }else{
            utility.writeFile(destFolder+utility.nameFile(pathToVerify)+"_"+this.myID+".unvalid_mt", myDoc);    
        }
        File f = new File(utility.getPathFolder("readyTSA_" + this.tsaID + "/")+this.mappingNameFromOriginal.get(pathToVerify));
        Files.delete(f.toPath()); //elimino l'elelemento servito
        return intestVect;
    }

    private byte[] constructRoot(byte[] hi, byte[] sequence) throws IOException, NoSuchAlgorithmException {
        
        byte firstFusion = sequence[0];
        byte[] brotherLeaf = Arrays.copyOfRange(sequence, 1, 33);
        byte secondFusion = sequence[33];
        byte[] firstBrother = Arrays.copyOfRange(sequence, 34, 66);
        byte thirdFusion = sequence[66];
        byte[] lastBrother = Arrays.copyOfRange(sequence, 67, sequence.length);
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

    public boolean checkChain(int frame) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        boolean check=false;
       String[] filesPath = utility.getPathFiles("Public");
        if (filesPath.length != 0) {
            Journal j = new Journal();
            j.load(filesPath[0]);
            List <byte[]> shList=j.getListSH();
            List<byte[]> rhList=j.getListRH();
            for(int i=1;i<frame;i++){
                if(Arrays.equals(shList.get(i),utility.toHash256(utility.concatByte(shList.get(i-1),rhList.get(i-1))))){
                    check=true;
                }else {
                    return false;
                }
            }
            }
        return check;
    }
    
    public boolean checkAllChain() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        String[] filesPath = utility.getPathFiles("Public");
        boolean check=false;
        Journal j = new Journal();
        j.load(filesPath[0]);
        check=this.checkChain(j.getTF());
        return check;
    }

}
