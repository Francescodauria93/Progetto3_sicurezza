/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 *
 * @author dp.alex
 */
public class TSA {
    
    public void merkelTree(){
        
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myDirectoryPath = s + "/folderWaitingFiles";
        File dir = new File(myDirectoryPath);
        File[] directoryListing = dir.listFiles();
        
        if (directoryListing != null) {
            
        for (File child : directoryListing) {
            
            System.out.println(child);
            
            }
        }
        
    }
        
     
    }
