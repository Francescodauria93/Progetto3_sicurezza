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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
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

    public void merkelTree() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderWaitingFiles";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles();

        if (directoryListing.length != 8) { // riempio
            this.fillWaiting();
        }

        byte[] readByteEnc = null; //byte letti temporanei
        List<String> hID = new ArrayList<String>(); // lista di id
        List<byte[]> hlist = new ArrayList<byte[]>();    //lista di h
        List<byte[]> levelFour = new ArrayList<byte[]>();    // livello di 4 elementi
        List<byte[]> levelTwo = new ArrayList<byte[]>();   //livello di 2 elementi
        byte[] hashRoot = new byte[32]; // root Hash

        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "CBC", "PKCS1Padding");
        PrivateKey tsaPK = null;
        // qui costruisco hlist e hID
        for (File child : directoryListing) {
            readByteEnc = fileUtility.loadFile(child.toString()); // leggo il file
            byte[] readByte = cipherUtility.asimmetricDecode(c, readByteEnc, tsaPK);
            byte[] h_tmp = Arrays.copyOfRange(readByte, 0, 32); //hash temporaneo
            String currID = Arrays.copyOfRange(readByte, 32, readByte.length).toString();
            hID.add(currID);
            String timeStamp = fileUtility.getTimeFromServer("GMT"); //prendo il timeStamp
            mapTimeStamp.put(currID, timeStamp);
            hlist.add(fileUtility.concatByte(h_tmp, timeStamp.getBytes()));//inseristo nella lista degli hash il documento hashato seguito dal timeStamp
        }

        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA

        for (int i = 0; i < 8; i += 2) { // costruisco il terzo livello
            sha.update(fileUtility.concatByte(hlist.get(i), hlist.get(i + 1)));
            levelFour.add(sha.digest());
        }
        for (int i = 0; i < 4; i += 2) { // costruisco il secondo livello
            sha.update(fileUtility.concatByte(levelFour.get(i), levelFour.get(i + 1)));
            levelTwo.add(sha.digest());
        }
        sha.update(fileUtility.concatByte(levelTwo.get(0), levelTwo.get(1))); // costruisco la root
        hashRoot = (sha.digest());

        byte[] preSuperHash = this.getPreSuperHash(); // carico la superHashprecedente
        sha.update(fileUtility.concatByte(preSuperHash, hashRoot));
        byte[] newSuperHash = sha.digest();  // costruisco la nuova publicSuperHash
        this.sendPublicSuperHash(newSuperHash); // la pubblico
        this.sendPublicHash(hashRoot);   // pubblico anche l'hash

        this.createPath(hlist, levelFour, levelTwo, hID);

        
        this.timeframenumber += 1; // aggiorno il timeframe
    }

    private void createPath(List<byte[]> leaf, List<byte[]> l2, List<byte[]> l1, List<String> listID) throws IOException {
        byte dx = "d".getBytes()[0];
        byte sx = "s".getBytes()[0];
        this.allMapPath.put(listID.get(0), fileUtility.concatMerkleByte(dx, leaf.get(1), dx, l2.get(1), dx, l1.get(1)));
        this.allMapPath.put(listID.get(1), fileUtility.concatMerkleByte(sx, leaf.get(0), dx, l2.get(1), dx, l1.get(1)));
        this.allMapPath.put(listID.get(2), fileUtility.concatMerkleByte(dx, leaf.get(3), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(listID.get(3), fileUtility.concatMerkleByte(sx, leaf.get(2), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(listID.get(4), fileUtility.concatMerkleByte(dx, leaf.get(5), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(listID.get(5), fileUtility.concatMerkleByte(sx, leaf.get(4), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(listID.get(6), fileUtility.concatMerkleByte(dx, leaf.get(7), sx, l2.get(2), sx, l1.get(0)));
        this.allMapPath.put(listID.get(7), fileUtility.concatMerkleByte(sx, leaf.get(6), sx, l2.get(2), sx, l1.get(0)));
    }

    private void sendPublicHash(byte[] hash) throws IOException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderPublicRootHashValue";
        fileUtility.writeFile(myDirectoryPath + "/hash" + this.timeframenumber + ".hv", hash);

    }

    private void sendPublicSuperHash(byte[] superHash) throws IOException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderPublicSuperHashValue";
        fileUtility.writeFile(myDirectoryPath + "/superhash" + this.timeframenumber + ".shv", superHash);
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
            fileUtility.writeFile(path, completeDocument);
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
        fileUtility.writeFile(myDirectoryPath + "/superhash0.shv", sha.digest());

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

        byte[] preSH = fileUtility.loadFile(myDirectoryPath + "/superhash" + (currentTimeFrame - 1) + ".shv");
        return preSH;

    }

}
