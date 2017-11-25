/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.util.Arrays;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author dp.alex
 */
public class TSA {

    public void merkelTree() throws IOException, NoSuchAlgorithmException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderWaitingFiles";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles();

        if (directoryListing.length != 8) { // riempio
            this.fillWaiting();
        }

        byte[] readByte = null; //byte letti temporanei
        List<String> hID = new ArrayList<String>(); // lista di id
        List<byte[]> hlist = new ArrayList<byte[]>();    //lista di h
        List<byte[]> levelFour = new ArrayList<byte[]>();    // livello di 4 elementi
        List<byte[]> levelTwo = new ArrayList<byte[]>();   //livello di 2 elementi
        String hashRoot ; // root Hash
        
       // qui costruisco hlist e hID
        for (File child : directoryListing) {
            readByte = fileUtility.loadFile(child.toString()); // leggo il file
            int len = (int)Arrays.copyOfRange(readByte, 0, 1)[0];
            hID.add(Arrays.copyOfRange(readByte, 1, len + 1).toString());
            hlist.add(Arrays.copyOfRange(readByte, len + 1, readByte.length));
        }
        
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA
        
        for(int i =0;i<8;i+=2){
            sha.update(fileUtility.concatByte(hlist.get(i), hlist.get(i+1)));
            levelFour.add(sha.digest());
        }
        for(int i =0;i<4;i+=2){
            sha.update(fileUtility.concatByte(levelFour.get(i), levelFour.get(i+1)));
            levelTwo.add(sha.digest());
        }
     

    }

    public void fillWaiting() {

    }

  
}
