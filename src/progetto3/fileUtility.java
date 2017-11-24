/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 *
 * @author dp.alex
 */
public class fileUtility implements Serializable {

    public static String nameFile(String sourcePath) {
        File file = new File(sourcePath);
        return file.getName();
    }

    public static byte[] loadFile(String sourcePath) throws IOException {
        Path path = Paths.get(sourcePath);
        byte[] data = Files.readAllBytes(path);
        return data;
    }

    public static void writeFile(String sourcePath, byte[] output) throws IOException {
        Path path = Paths.get(sourcePath);
        Files.write(path, output);

    }

}
