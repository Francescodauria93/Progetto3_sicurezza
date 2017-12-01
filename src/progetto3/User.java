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
    private String indexDsaUsedbyTsa = "1";
    private String tsaID;
    private KeyRing myKR;
    private Map<String, String> mappingNameFromOriginal = new HashMap<String, String>();

    public User(String myID) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        this.myID = myID;
        this.myKR = new KeyRing();
        String kRFolder = utility.getPathFolder("wallet/");
        this.myKR.loadKeyRing(kRFolder + this.myID + ".w", this.myID + "pass");

    }

    public void sendDocumentToTSA(String pathFile, String idTsa, String i) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        this.indexRsaUsedbyMe = i;
        this.tsaID = idTsa;
        //preparo byte da inviare
        byte[] myID = this.myID.getBytes();
        byte[] hashFileReaded = utility.toHash256(utility.loadFile(pathFile));

        //creo un ByteArrayOutputStream per concatenare gli array di byte
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(hashFileReaded);
        outputStream.write(myID);
        byte completeDocument[] = outputStream.toByteArray();

        //chiudo lo stram e scrivo l'array di byte appena concatenato
        outputStream.close();
        //creo istanza cifrario RSA
        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "ECB", "PKCS1Padding");
        byte[] DocumentEncrypted = cipherUtility.asimmetricEncode(c, completeDocument, this.myKR.getPublicKey("RSA", this.tsaID + "_chiave1024_" + this.indexDsaUsedbyTsa));
        //salvo tutto in documento_ID_user.toTsa
        String destFolder = utility.getPathFolder("inboxTSA_" + idTsa + "/");
        String indexName = utility.getIndexNameToSave(this.myID, utility.getPathFolder("inboxTSA_" + idTsa + "/"));
        this.mappingNameFromOriginal.put(pathFile, this.myID + "-" + indexName);
        utility.writeFile(destFolder + this.myID + "-" + indexName, DocumentEncrypted);

    }

    public String[] checkValidity(String pathToVerify) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException {

        String pathFile = utility.getPathFolder("repoperprogetto3/");
        String name = utility.nameFile(pathToVerify);

        byte[] localFileHash = utility.toHash256(utility.loadFile(pathFile + name.substring(0, name.indexOf("("))));
        byte[] myDoc = utility.loadFile(pathToVerify);
        int size_intest = (int) myDoc[0];
        byte[] intest = Arrays.copyOfRange(myDoc, 1, size_intest + 1);
        String[] intestVect = utility.intestToStringArray(intest, 5);
        byte[] hi = Arrays.copyOfRange(myDoc, size_intest + 1, size_intest + 1 + 32);
        byte[] sequenceMerkle = Arrays.copyOfRange(myDoc, size_intest + 1 + 32, size_intest + 1 + 32 + 99);
        byte[] sh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99, size_intest + 1 + 32 + 99 + 32);
        byte[] preSh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32, size_intest + 1 + 32 + 99 + 32 + 32);
        byte[] sign = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32 + 32, myDoc.length);
        byte[] arrayToVerify = Arrays.copyOfRange(myDoc, 0, myDoc.length - sign.length);
        byte[] myHi = utility.toHash256(utility.concatByte(localFileHash, intestVect[4].getBytes()));
        byte[] rootHash = this.constructRoot(hi, sequenceMerkle);
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        sha.update(utility.concatByte(preSh, rootHash));
        byte[] shC = sha.digest();
        Boolean checkSign = utility.verifySign(arrayToVerify, sign, this.myKR.getPublicKey("DSA", this.tsaID + "_chiave1024_" + this.indexDsaUsedbyTsa), intestVect[3]);
        Boolean checkLeaf = Arrays.equals(myHi, hi);
        Boolean checkRhSh = Arrays.equals(sh, shC);
        return this.logMessage(intestVect, pathToVerify, checkSign, checkLeaf, checkRhSh);
    }

    public void receivesMyMeesages() throws IOException {
        String pathReadyTsa = utility.getPathFolder("readyTSA_" + this.tsaID + "/");
        String destFolder = utility.getPathFolder("InboxUsers/");
        for (Map.Entry<String, String> entry : this.mappingNameFromOriginal.entrySet()) {

            byte[] myDoc = utility.loadFile(pathReadyTsa + entry.getValue());
            int size_intest = (int) myDoc[0];
            byte[] intest = Arrays.copyOfRange(myDoc, 1, size_intest + 1);
            String[] intestVect = utility.intestToStringArray(intest, 5);
            utility.writeFile(destFolder + utility.nameFile(entry.getKey()) + "(" + intestVect[0] + "_" + intestVect[4].replace(' ', '_').substring(0, 10) + ")", myDoc);

        }
    }

    private String[] logMessage(String[] intest, String namefile, boolean sign, boolean leaf, boolean RhSh) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        String[] log = new String[10];
        log[0] = "Id Mittente: " + intest[0];
        log[1] = "Id Tsa: " + intest[1];
        log[2] = "NTree marca temporale: " + intest[2];
        log[3] = "Algoritmo di sgnature Tsa: " + intest[3];
        log[4] = "Timestamp: " + intest[4];
        log[5] = "Nome file marcato: " + utility.nameFile(namefile);
        log[6] = "Validità firma Tsa: " + sign;
        log[7] = "Corrispondeza documento Hashato+timestamp e foglia dell'albero di Merkle: " + leaf;
        log[8] = "Validità Sh=hash(Sh-1,Rh): " + RhSh;
        log[9] = "Verifica dell' intera catena in avanti e indietro dall NTree (" + intest[2] + "): " + this.checkChain(namefile);

        return log;
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

    public boolean checkChain(String pathToVerify) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        boolean check = false;
        String[] filesPath = utility.getPathFiles("Public");
        if (filesPath.length != 0) {
            Journal j = new Journal();
            j.load(filesPath[0]);
            List<byte[]> shList = j.getListSH();
            List<byte[]> rhList = j.getListRH();
            byte[] myDoc = utility.loadFile(pathToVerify);
            int size_intest = (int) myDoc[0];
            byte[] intest = Arrays.copyOfRange(myDoc, 1, size_intest + 1);
            String[] intestVect = utility.intestToStringArray(intest, 5);
            byte[] sh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99, size_intest + 1 + 32 + 99 + 32);
            byte[] preSh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32, size_intest + 1 + 32 + 99 + 32 + 32);
            if (Arrays.equals(sh, shList.get(Integer.parseInt(intestVect[2])))) {
                for (int i = 1; i < Integer.parseInt(intestVect[2]); i++) {
                    if (Arrays.equals(shList.get(i), utility.toHash256(utility.concatByte(shList.get(i - 1), rhList.get(i - 1))))) {
                        check = true;
                    } else {
                        return false;
                    }

                }
                for (int i = Integer.parseInt(intestVect[2]); i < shList.size(); i++) {
                    if (Arrays.equals(shList.get(i), utility.toHash256(utility.concatByte(shList.get(i - 1), rhList.get(i - 1))))) {
                        check = true;
                    } else {
                        return false;
                    }

                }
            }
        }
        return check;
    }

}
