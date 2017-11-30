/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import java.io.File;
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
import java.util.ArrayList;
import java.util.Base64;
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
    private int timeframenumber ;
    private Map<String, byte[]> allMapPath = new HashMap<String, byte[]>();
    private List<String> hID = new ArrayList<String>(); // lista di id
    private String idTsa = "Tsa1";
    private String typeSign="SHA256withDSA";
    private PrivateKey signKey;
    
    
    public TSA(PrivateKey signKey) throws ClassNotFoundException, IOException {
        this.signKey=signKey;
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/Public";
        File dir = new File(myDirectoryPath);
        String[] directoryListing = dir.list(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
            return !name.equals(".DS_Store");
        }
        });
        
        
        if(directoryListing.length!=0){
            Journal j = new Journal();
            j.load(myDirectoryPath+"/"+"Public.j");
            this.timeframenumber=j.byteListSH.size();
        }else{
            this.timeframenumber=1;
        }
        
        
    }
    
    
    
    public void start(PrivateKey tsaPK) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, ClassNotFoundException{
        //semplificazione del tempo che intercorre tra un timeframe ed un altro
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/inboxTSA_"+this.idTsa+"/";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
            return !name.equals(".DS_Store");
        }
        });
        

        if(directoryListing.length>8){  //se ci sono più di 8 file in coda fai anche gli altri
            this.merkelTree(tsaPK);
            this.start(tsaPK);
        }else{
            this.merkelTree(tsaPK);
        }

    }
   
    public void merkelTree(PrivateKey tsaPK) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, ClassNotFoundException {

        
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/inboxTSA_"+this.idTsa+"/";
        File dir = new File(myDirectoryPath);
        
        //File[] directoryListing = dir.listFiles();
        String[] directoryListing = dir.list(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
            return !name.equals(".DS_Store");
        }
        });
        
        List<String> filelist ;  // prendo in cosiderazione solo 8 elementi
        boolean fill = false;    // controllo se fill
        
        if(directoryListing.length>=8){
        filelist = Arrays.asList(directoryListing).subList(0, 8);
        }else{
            filelist = Arrays.asList(directoryListing).subList(0, directoryListing.length);
            fill=true;
        }
        
       
        byte[] readByteEnc = null; //byte letti temporanei
        
        List<byte[]> hlist = new ArrayList<byte[]>();    //lista di h
        List<byte[]> levelFour = new ArrayList<byte[]>();    // livello di 4 elementi
        List<byte[]> levelTwo = new ArrayList<byte[]>();   //livello di 2 elementi
        byte[] hashRoot = new byte[32]; // root Hash

        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "ECB", "PKCS1Padding");
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        // qui costruisco hlist e hID
        for (String path : filelist) {
            
            readByteEnc = utility.loadFile(myDirectoryPath +path); // leggo il file
            byte[] readByte = cipherUtility.asimmetricDecode(c, readByteEnc, tsaPK);
            byte[] h_tmp = Arrays.copyOfRange(readByte, 0, 32); //hash temporaneo
            String currID = new String(Arrays.copyOfRange(readByte, 32, readByte.length));
            this.hID.add(currID);
            String timeStamp = utility.getTimeFromServer("GMT"); //prendo il timeStamp
            this.mapTimeStamp.put(currID, timeStamp);
            sha.update(utility.concatByte(h_tmp, timeStamp.getBytes()));
            hlist.add(sha.digest());//inseristo nella lista degli hash il documento hashato seguito dal timeStamp
            File f = new File(myDirectoryPath +path);
            Files.delete(f.toPath()); //elimino l'elelemento servito
            

        }
        
        if (fill) { // riempio
            List<byte[]> fillNode = new ArrayList<byte[]>();
            fillNode = this.fillWaiting(this.idTsa);
            
            for(byte[] child : fillNode){
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

        this.createPath(hlist, levelFour, levelTwo );
        this.sendAll(hlist);
        this.clearAll();
        this.timeframenumber += 1; // aggiorno il timeframe
    }
    
    private void clearAll(){
        this.allMapPath.clear();
        this.hID.clear();
        this.mapTimeStamp.clear();
    }

    private void createPath(List<byte[]> leaf, List<byte[]> l2, List<byte[]> l1 ) throws IOException {
        
        System.out.print("***********************");
        byte dx = 0;
        byte sx = 1;
        this.allMapPath.put(this.hID.get(0), utility.concatMerkleByte(dx, leaf.get(1), dx, l2.get(1), dx, l1.get(1)));
        System.out.println(this.hID.get(0));
        System.out.println(Base64.getEncoder().encodeToString(leaf.get(1)));
        System.out.println(Base64.getEncoder().encodeToString(l2.get(1)));
        System.out.println(Base64.getEncoder().encodeToString(l1.get(1)));
        this.allMapPath.put(this.hID.get(1), utility.concatMerkleByte(sx, leaf.get(0), dx, l2.get(1), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(2), utility.concatMerkleByte(dx, leaf.get(3), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(3), utility.concatMerkleByte(sx, leaf.get(2), sx, l2.get(0), dx, l1.get(1)));
        this.allMapPath.put(this.hID.get(4), utility.concatMerkleByte(dx, leaf.get(5), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(5), utility.concatMerkleByte(sx, leaf.get(4), dx, l2.get(3), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(6), utility.concatMerkleByte(dx, leaf.get(7), sx, l2.get(2), sx, l1.get(0)));
        this.allMapPath.put(this.hID.get(7), utility.concatMerkleByte(sx, leaf.get(6), sx, l2.get(2), sx, l1.get(0)));
    }

    private void savePublicHash(byte[] hash) throws IOException, ClassNotFoundException, ClassNotFoundException {  //c

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String path = s + "/Public";
        Journal journal = new Journal();
        journal.load(path+"/Public.j");
        journal.byteListRH.add(hash);
        journal.save(path, "Public");

    }

    private void savePublicSuperHash(byte[] superHash) throws IOException, ClassNotFoundException { //c

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String path = s + "/Public";
        Journal journal = new Journal();
        journal.load(path+"/Public.j");
        journal.byteListSH.add(superHash);
        journal.save(path, "Public");
        //String lines[] = utility.readTxt(myDirectoryPath+"PublicSHJournal.txt").split("\\r?\\n");
  
    }

    private List<byte[]> fillWaiting(String idTsa) throws NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException {
       
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/inboxTSA_"+this.idTsa+"/";
        
        
        File dir = new File(myDirectoryPath);
        //File[] directoryListing = dir.listFiles();
        File[] directoryListing = dir.listFiles(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
            return !name.equals(".DS_Store");
        }
        }); 
        
        
        int fNumber = 8 - directoryListing.length;// quanti da aggiungere
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

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String path = s + "/Public";

        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        sha.update(bytes);
        
        Journal journal = new Journal();
        journal.byteListSH.add(sha.digest());
    
        journal.save(path,"Public");
 
    }

    private byte[] getPreSuperHash() throws IOException, NoSuchAlgorithmException, ClassNotFoundException { //cambiare

        int currentTimeFrame = this.timeframenumber;
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String path = s + "/Public";
        File dir = new File(path);
        File[] directoryListing = dir.listFiles(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
            return !name.equals(".DS_Store");
        }
        });

        if (directoryListing.length == 0) {
            this.startSuperHash();
        }
        
        Journal journal = new Journal();
        journal.load(path+"/Public.j");
        return journal.byteListSH.get(currentTimeFrame - 1);
        


    }
    
    private void sendAll(List<byte[]> hlist) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException{
    //intestazione Stringa trasformata in byte[]:  "idMitt/idTsa/#diserie(timeframe)/tipo_di_alg_firma/timestampfoglia i-esima"
    //formato timeStamp: lunghezza intest in byte + intest in byte + hi (foglia i-esima) + sequenzaalbero + sh + sh-1 + firmaTSA
    

    Path currentRelativePath = Paths.get("src/progetto3");
    String s = currentRelativePath.toAbsolutePath().toString();
    
    String path = s + "/Public";
    
    Journal j = new Journal();
    j.load(path+"/Public.j");
    
    byte[] sh=j.byteListSH.get(this.timeframenumber);
    byte[] preSh=j.byteListSH.get(this.timeframenumber-1);
    byte[] rootHash = j.byteListRH.get(this.timeframenumber-1);
    System.out.println("root -> "+Base64.getEncoder().encodeToString(rootHash));
        System.out.println("preSH -> "+Base64.getEncoder().encodeToString(preSh));
        System.out.println("SH - > "+Base64.getEncoder().encodeToString(sh));
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    for(int i=0;i<8;i++){
        if(!this.hID.get(i).matches(".*(fakeID).*")){
            System.out.println("TSA-mitt: "+this.hID.get(i));
            byte[] intest=(this.hID.get(i)+"/"+this.idTsa+"/"+this.timeframenumber+"/"+this.typeSign+"/"+this.mapTimeStamp.get(this.hID.get(i))+"/").getBytes();
             outputStream.write(intest.length);
             outputStream.write(intest);
             System.out.println(intest.length);
             outputStream.write(hlist.get(i));
             System.out.println("h1 -> "+Base64.getEncoder().encodeToString(hlist.get(i)));
             outputStream.write(this.allMapPath.get(this.hID.get(i)));
             System.out.println(this.allMapPath.get(this.hID.get(i)).length);
             outputStream.write(sh);
             System.out.println(sh.length);
             outputStream.write(preSh);
             System.out.println(preSh.length);
             byte[] signature=utility.sign(outputStream.toByteArray(), this.signKey, this.typeSign);
             System.out.println(signature.length);
             outputStream.write(signature);
            byte[]  tmp= outputStream.toByteArray();
            System.out.println(tmp.length + this.hID.get(i));
            utility.writeFile(currentRelativePath+ "/readyTSA_"+this.idTsa+"/"+ this.hID.get(i)+".mt",tmp);
            

        }
        outputStream.flush();
        }
    outputStream.close();

    }

}
