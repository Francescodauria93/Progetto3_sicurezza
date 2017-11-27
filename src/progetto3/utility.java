/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 *
 * @author dp.alex
 */
public class utility implements Serializable {

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

    public static String getTimeFromServer(String id) {
        String time;
        final Date currentTime = new Date();
        final SimpleDateFormat sdf = new SimpleDateFormat("EEE, MMM d, yyyy hh:mm:ss a z");
        sdf.setTimeZone(TimeZone.getTimeZone(id));
        return sdf.format(currentTime);
    }

    public static String[] getTimeIdServer() {
        String ids[] = TimeZone.getAvailableIDs();
        return ids;
    }

    public static byte[] concatByte(byte a[], byte[] b) throws IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(a);
        outputStream.write(b);
        byte c[] = outputStream.toByteArray();
        outputStream.close();
        return c;
    }
    
        public static byte[] concatMerkleByte(byte a, byte[] b,byte c, byte[] d,byte e, byte[] f) throws IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(a);
        outputStream.write(b);
        outputStream.write(c);
        outputStream.write(d);
        outputStream.write(e);
        outputStream.write(f);
        
        byte tmp[] = outputStream.toByteArray();
        outputStream.close();
        return tmp;
    }
        
    public static byte[] sign(byte[] textToSign, PrivateKey userKeyPr, String alg) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        if(alg.matches("SHA1withDSA") || alg.matches("SHA224withDSA") || alg.matches("SHA256withDSA")){
            Signature dsa = Signature.getInstance(alg);
            dsa.initSign(userKeyPr);
            dsa.update(textToSign);
            return dsa.sign();
        }
        else{
            return null;
        }
        
    }
    
    public static boolean verifySign(byte[] signedText, byte[] firma, PublicKey userKeyPub, String padding) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        Signature dsa = Signature.getInstance(padding);
        dsa.initVerify(userKeyPub);
	dsa.update(signedText);
	return dsa.verify(firma);
    }

}
