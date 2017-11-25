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

/**
 *
 * @author dp.alex
 */
public class TSA {

    public void merkelTree() throws IOException {

        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderWaitingFiles";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles();

        if (directoryListing.length != 8) { // riempio
            this.fillWaiting();
        }

        byte[] readByte = null;
        for (File child : directoryListing) {
            readByte = fileUtility.loadFile(child.toString()); // leggo il file
            
        }

    }

    public void fillWaiting() {

    }

    public static void readDoc() {
        //questo è quello che leggi da file
        byte[] fileReaded = null;
        byte[] docFile = new byte[32];
        byte[] userID = null;
        //carico l'hash del file nel suo array di byte 

        docFile = Arrays.copyOfRange(fileReaded, 0, 32);
        userID = Arrays.copyOfRange(fileReaded, 32 + 1, fileReaded.length);

    }

}
