/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;

/**
 *
 * @author dp.alex
 */
public class TSA {

    private Map<String, String> mapTimeStamp = new HashMap<String, String>();
    private int timeframenumber = 1;
    private Map<String, byte[]> allMapPath = new HashMap<String, byte[]>();
    private List<String> hID = new ArrayList<String>(); // lista di id
    
    public void merkelTree() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderWaitingFiles";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles();

        if (directoryListing.length != 8) { // riempio
            this.fillWaiting();
        }

        byte[] readByteEnc = null; //byte letti temporanei
        
        List<byte[]> hlist = new ArrayList<byte[]>();    //lista di h
        List<byte[]> levelFour = new ArrayList<byte[]>();    // livello di 4 elementi
        List<byte[]> levelTwo = new ArrayList<byte[]>();   //livello di 2 elementi
        byte[] hashRoot = new byte[32]; // root Hash

        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "CBC", "PKCS1Padding");
        PrivateKey tsaPK = null;
        // qui costruisco hlist e hID
        for (File child : directoryListing) {
            readByteEnc = utility.loadFile(child.toString()); // leggo il file
            byte[] readByte = cipherUtility.asimmetricDecode(c, readByteEnc, tsaPK);
            byte[] h_tmp = Arrays.copyOfRange(readByte, 0, 32); //hash temporaneo
            String currID = Arrays.copyOfRange(readByte, 32, readByte.length).toString();
            this.hID.add(currID);
            String timeStamp = utility.getTimeFromServer("GMT"); //prendo il timeStamp
            this.mapTimeStamp.put(currID, timeStamp);
            hlist.add(utility.concatByte(h_tmp, timeStamp.getBytes()));//inseristo nella lista degli hash il documento hashato seguito dal timeStamp
        }

        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA

        for (int i = 0; i < 8; i += 2) { // costruisco il terzo livello
            sha.update(utility.concatByte(hlist.get(i), hlist.get(i + 1)));
            levelFour.add(sha.digest());
        }
        for (int i = 0; i < 4; i += 2) { // costruisco il secondo livello
            sha.update(utility.concatByte(levelFour.get(i), levelFour.get(i + 1)));
            levelTwo.add(sha.digest());
        }
        sha.update(utility.concatByte(levelTwo.get(0), levelTwo.get(1))); // costruisco la root
        hashRoot = (sha.digest());

        byte[] preSuperHash = this.getPreSuperHash(); // carico la superHashprecedente
        sha.update(utility.concatByte(preSuperHash, hashRoot));
        byte[] newSuperHash = sha.digest();  // costruisco la nuova publicSuperHash
        this.sendPublicSuperHash(newSuperHash); // la pubblico
        this.sendPublicHash(hashRoot);   // pubblico anche l'hash

        this.createPath(hlist, levelFour, levelTwo);
        this.sendAll(hlist);
        
        this.timeframenumber += 1; // aggiorno il timeframe
    }

    private void createPath(List<byte[]> leaf, List<byte[]> l2, List<byte[]> l1) throws IOException {
        byte dx = "d".getBytes()[0];
        byte sx = "s".getBytes()[0];
        this.allMapPath.put(this.hID.get(0), utility.concatMerkleByte(dx, leaf.get(1), dx, l2.get(1), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(1), utility.concatMerkleByte(sx, leaf.get(0), dx, l2.get(1), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(2), utility.concatMerkleByte(dx, leaf.get(3), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(3), utility.concatMerkleByte(sx, leaf.get(2), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(4), utility.concatMerkleByte(dx, leaf.get(5), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(5), utility.concatMerkleByte(sx, leaf.get(4), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(6), utility.concatMerkleByte(dx, leaf.get(7), sx, l2.get(2), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(7), utility.concatMerkleByte(sx, leaf.get(6), sx, l2.get(2), sx, l1.get(0)));
    }

    private void sendPublicHash(byte[] hash) throws IOException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderPublicRootHashValue";
        utility.writeFile(myDirectoryPath + "/hash" + this.timeframenumber + ".hv", hash);

    }

    private void sendPublicSuperHash(byte[] superHash) throws IOException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderPublicSuperHashValue";
        utility.writeFile(myDirectoryPath + "/superhash" + this.timeframenumber + ".shv", superHash);
    }

    private void fillWaiting() throws NoSuchAlgorithmException, IOException {
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderWaitingFiles";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles();
        int fNumber = 8 - directoryListing.length;// quanti da aggiungere

        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        byte[] id = ("fakeID").getBytes();

        int i = 0;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        while (i < fNumber) {

            random.nextBytes(bytes);
            sha.update(bytes);
            outputStream.write(sha.digest());
            outputStream.write(id);
            byte completeDocument[] = outputStream.toByteArray();
            outputStream.flush();
            String path = myDirectoryPath + "/fakeID" + i + ".toTSA";
            utility.writeFile(path, completeDocument);
            i += 1;

        }
        outputStream.close(); //chiudo lo stream dopo aver inviato tutto

    }

    private void startSuperHash() throws NoSuchAlgorithmException, IOException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderPublicSuperHashValue";

        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);

        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        sha.update(bytes);
        utility.writeFile(myDirectoryPath + "/superhash0.shv", sha.digest());

    }

    private byte[] getPreSuperHash() throws IOException, NoSuchAlgorithmException {

        int currentTimeFrame = this.timeframenumber;
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderPublicSuperHashValue";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles();

        if (directoryListing.length == 0) {
            this.startSuperHash();
        }

        byte[] preSH = utility.loadFile(myDirectoryPath + "/superhash" + (currentTimeFrame - 1) + ".shv");
        return preSH;

    }
    
    
    private void sendAll(List<byte[]> hlist) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
    //intestazione Stringa trasformata in byte[]:  "idMitt/idTsa/#diserie(timeframe)/tipo_di_alg_firma/timestampfoglia i-esima"
    //formato timeStamp: lunghezza intest in byte + intest in byte + hi (foglia i-esima) + sequenzaalbero + sh + sh-1 + firmaTSA
    
    String myID="TSA1";
    String typeSign="";
    PrivateKey privateKeyTsa=null;
    Path currentRelativePath = Paths.get("src/progetto3");
    String s = currentRelativePath.toAbsolutePath().toString();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    
    String myDirectoryPath = s + "/folderPublicSuperHashValue";
    String docWithTimeStampPath = s + "/folderdocWithTimeStamp";
    byte[] sh=utility.loadFile(myDirectoryPath + "/superhash" + this.timeframenumber + ".shv");
    byte[] preSh=utility.loadFile(myDirectoryPath + "/superhash" + (this.timeframenumber-1) + ".shv");
    
    for(int i=0;i<8;i++){
        if(!this.hID.get(i).matches(".*(fakeID).*")){
            byte[] intest=(this.hID.get(i)+"/"+myID+"/"+this.timeframenumber+"/"+typeSign+"/"+this.mapTimeStamp.get(this.hID.get(i))+"/").getBytes();
             outputStream.write(intest.length);
             outputStream.write(intest);
             outputStream.write(hlist.get(i));
             outputStream.write(this.allMapPath.get(this.hID.get(i)));
             outputStream.write(sh);
             outputStream.write(preSh);
             outputStream.write(utility.sign(outputStream.toByteArray(), privateKeyTsa, typeSign));
            byte[]  tmp= outputStream.toByteArray();
            utility.writeFile(myDirectoryPath+ "/docWithTimeStamp-frame#" + this.timeframenumber +"-"+this.hID.get(i), tmp);
            outputStream.flush();
            
        
        }
        }
    outputStream.close();

    }

}
