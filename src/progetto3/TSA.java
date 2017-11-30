/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
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
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author dp.alex
 */
public class TSA {

    private Map<String, String> mapTimeStamp;
    private Map<String, byte[]> allMapPath;
    private List<String> hID;

    private int timeframenumber;
    private String idTsa = "Tsa1";
    private String typeSign = "SHA256withDSA";
    private PrivateKey signKey;
    private PrivateKey encKey;

    public TSA() throws ClassNotFoundException, IOException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        KeyRing kTsa = new KeyRing();
        kTsa.loadKeyRing(utility.getPathFolder("wallet") + "/tsa.w", "tsapass");
        this.signKey = kTsa.getMyPrivateSignature("DSA", "chiave1024_1");
        this.encKey = kTsa.getMyPrivateAsimmetric("RSA", "chiave1024_1");
        this.mapTimeStamp = new HashMap<String, String>();
        this.allMapPath = new HashMap<String, byte[]>();
        this.hID = new ArrayList<String>(); // lista di id

        String[] filesPath = utility.getPathFiles("Public");

        if (filesPath.length != 0) {
            Journal j = new Journal();
            j.load(filesPath[0]);
            this.timeframenumber = j.getTF();
        } else {
            this.timeframenumber = 1;
        }

    }

    public void start() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, ClassNotFoundException {
        //semplificazione del tempo che intercorre tra un timeframe ed un altro
        String[] filesPath = utility.getPathFiles("inboxTSA_" + this.idTsa);

        if (filesPath.length > 8) {  //se ci sono più di 8 file in coda fai anche gli altri
            this.merkelTree();
            this.start();
        } else {
            this.merkelTree();
        }

    }

    public void merkelTree() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, ClassNotFoundException {

        String[] filesPath = utility.getPathFiles("inboxTSA_" + this.idTsa);

        List<String> filelist;  // prendo in cosiderazione solo 8 elementi
        boolean fill = false;    // controllo se fill

        if (filesPath.length >= 8) {
            filelist = Arrays.asList(filesPath).subList(0, 8);
        } else {
            filelist = Arrays.asList(filesPath).subList(0, filesPath.length);
            fill = true;
        }

        byte[] readByteEnc; //byte letti temporanei

        List<byte[]> hlist = new ArrayList<byte[]>();    //lista di h
        List<byte[]> levelFour = new ArrayList<byte[]>();    // livello di 4 elementi
        List<byte[]> levelTwo = new ArrayList<byte[]>();   //livello di 2 elementi
        byte[] hashRoot = new byte[32]; // root Hash

        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "ECB", "PKCS1Padding");
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        // qui costruisco hlist e hID
        for (String path : filelist) {

            readByteEnc = utility.loadFile(path); // leggo il file
            byte[] readByte = cipherUtility.asimmetricDecode(c, readByteEnc, this.encKey);
            byte[] h_tmp = Arrays.copyOfRange(readByte, 0, 32); //hash temporaneo
            String currID = new String(Arrays.copyOfRange(readByte, 32, readByte.length));
            String timeStamp = utility.getTimeFromServer("GMT"); //prendo il timeStamp
            this.hID.add(currID);
            this.mapTimeStamp.put(currID, timeStamp);
            sha.update(utility.concatByte(h_tmp, timeStamp.getBytes()));
            hlist.add(sha.digest());//inseristo nella lista degli hash il documento hashato seguito dal timeStamp

            File f = new File(path);
            Files.delete(f.toPath()); //elimino l'elelemento servito

        }

        if (fill) { // riempio
            List<byte[]> fillNode = new ArrayList<byte[]>();
            fillNode = this.fillWaiting(this.idTsa);

            for (byte[] child : fillNode) {
                hlist.add(child);
                this.hID.add("fakeID");
            }
        }

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
        this.savePublicSuperHash(newSuperHash); // la pubblico
        this.savePublicHash(hashRoot);   // pubblico anche l'hash

        this.createPath(hlist, levelFour, levelTwo);
        this.sendAll(hlist);
        this.clearAll();
        this.timeframenumber += 1; // aggiorno il timeframe
    }

    private void clearAll() {
        this.allMapPath.clear();
        this.hID.clear();
        this.mapTimeStamp.clear();
    }

    private void createPath(List<byte[]> leaf, List<byte[]> l2, List<byte[]> l1) throws IOException {

        byte dx = 0;
        byte sx = 1;
        this.allMapPath.put(this.hID.get(0), utility.concatMerkleByte(dx, leaf.get(1), dx, l2.get(1), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(1), utility.concatMerkleByte(sx, leaf.get(0), dx, l2.get(1), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(2), utility.concatMerkleByte(dx, leaf.get(3), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(3), utility.concatMerkleByte(sx, leaf.get(2), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(4), utility.concatMerkleByte(dx, leaf.get(5), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(5), utility.concatMerkleByte(sx, leaf.get(4), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(6), utility.concatMerkleByte(dx, leaf.get(7), sx, l2.get(2), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(7), utility.concatMerkleByte(sx, leaf.get(6), sx, l2.get(2), sx, l1.get(0)));

    }

    private void savePublicHash(byte[] hash) throws IOException, ClassNotFoundException, ClassNotFoundException {  //c

        String filesPath = utility.getPathFolder("Public");
        Journal journal = new Journal();
        journal.load(filesPath+"/Journal.j");
        journal.byteListRH.add(hash);
        journal.save(filesPath,"Journal");

    }

    private void savePublicSuperHash(byte[] superHash) throws IOException, ClassNotFoundException { //c

        String filesPath = utility.getPathFolder("Public");
        Journal journal = new Journal();
        journal.load(filesPath+"/Journal.j");
        journal.byteListSH.add(superHash);
        journal.save(filesPath,"Journal");

    }

    private List<byte[]> fillWaiting(String idTsa) throws NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException {

        String[] filesPath = utility.getPathFiles("inboxTSA_" + this.idTsa);

        int fNumber = 8 - filesPath.length;// quanti da aggiungere
        List<byte[]> node = new ArrayList<byte[]>();

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
            node.add(completeDocument);
            i += 1;

        }
        outputStream.close(); //chiudo lo stream dopo aver inviato tutto
        return node;

    }

    private void startSuperHash() throws NoSuchAlgorithmException, IOException { //cambiare

         String fileFolder = utility.getPathFolder("Public");

        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        sha.update(bytes);

        Journal journal = new Journal();
        journal.byteListSH.add(sha.digest());

        journal.save(fileFolder, "Journal");

    }

    private byte[] getPreSuperHash() throws IOException, NoSuchAlgorithmException, ClassNotFoundException { //cambiare

        int currentTimeFrame = this.timeframenumber;
        Path currentRelativePath = Paths.get("src/progetto3");
        String[] filesPath = utility.getPathFiles("Public");

        if (filesPath.length == 0) {
            this.startSuperHash();
        }
        filesPath = utility.getPathFiles("Public");
        
        Journal journal = new Journal();
        journal.load(filesPath[0]);
        return journal.byteListSH.get(currentTimeFrame - 1);

    }

    private void sendAll(List<byte[]> hlist) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException {
        //intestazione Stringa trasformata in byte[]:  "idMitt/idTsa/#diserie(timeframe)/tipo_di_alg_firma/timestampfoglia i-esima"
        //formato timeStamp: lunghezza intest in byte + intest in byte + hi (foglia i-esima) + sequenzaalbero + sh + sh-1 + firmaTSA

        String[] filesPath = utility.getPathFiles("Public");
        String pathFolder = utility.getPathFolder("readyTsa_"+this.idTsa);

        Journal j = new Journal();
        j.load(filesPath[0]);

        byte[] sh = j.byteListSH.get(this.timeframenumber);
        byte[] preSh = j.byteListSH.get(this.timeframenumber - 1);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        for (int i = 0; i < 8; i++) {
            if (!this.hID.get(i).matches(".*(fakeID).*")) {

                byte[] intest = (this.hID.get(i) + "/" + this.idTsa + "/" + this.timeframenumber + "/" + this.typeSign + "/" + this.mapTimeStamp.get(this.hID.get(i)) + "/").getBytes();
                outputStream.write(intest.length);
                outputStream.write(intest);
                outputStream.write(hlist.get(i));
                outputStream.write(this.allMapPath.get(this.hID.get(i)));
                outputStream.write(sh);
                outputStream.write(preSh);
                byte[] signature = utility.sign(outputStream.toByteArray(), this.signKey, this.typeSign);
                outputStream.write(signature);
                byte[] tmp = outputStream.toByteArray();
                utility.writeFile(pathFolder+"/"+this.hID.get(i)+utility.getIndexNameToSave(this.hID.get(i),pathFolder)+".mt", tmp);
                
            }
            outputStream.flush();
        }
        outputStream.close();
        
        j.incrementTF();
        j.save(utility.getPathFolder("Public"), "Journal");

    }

}
