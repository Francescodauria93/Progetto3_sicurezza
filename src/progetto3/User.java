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
import javax.crypto.*;

/**
 *
 * @author dp.alex
 */
public class User {

    public void sendDocumentToTSA(String pathFile, String id, String idTsa) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        byte[] myID = id.getBytes();
        byte[] fileReaded = utility.loadFile(pathFile);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(fileReaded);
        byte[] hashFileReaded = sha.digest();
        String nameFile = hashFileReaded.toString();
        //creo un ByteArrayOutputStream per concatenare gli array di byte
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(hashFileReaded);
        outputStream.write(myID);
        byte completeDocument[] = outputStream.toByteArray();
        //chiudo lo stram e scrivo l'array di byte appena concatenato
        outputStream.close();
        //creo istanza cifrario RSA
        PublicKey publicTSA = null;
        Cipher c = cipherUtility.getIstanceAsimmetricCipher("RSA", "CBC", "PKCS1Padding");
        byte[] DocumentEncrypted = cipherUtility.asimmetricEncode(c, completeDocument, publicTSA);
        //salvo tutto in documento_ID_user.toTsa
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();

        String destEncrypted = s + "/inboxTSA_" + idTsa + "/" + nameFile;
        utility.writeFile(destEncrypted, DocumentEncrypted);

    }

    public boolean checkValidity(boolean online, String idUser, PublicKey tsaKey, String pathFile) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Path currentRelativePath = Paths.get("src/progetto3");
        String s = currentRelativePath.toAbsolutePath().toString();
        String myInboxPath = s + "/inbox_" + idUser + "/";
        String shPath = s + "/folderPublicSuperHashValue";
        boolean check = false;
        byte[] myDoc = utility.loadFile(myInboxPath + utility.getNameFromHash(pathFile));
        //intestazione Stringa trasformata in byte[]:  "idMitt/idTsa/#diserie(timeframe)/tipo_di_alg_firma/timestampfoglia i-esima"
        //formato timeStamp: lunghezza intest in byte + intest in byte + hi (foglia i-esima) + sequenzaalbero + sh + sh-1 + firmaTSA
        int size_intest = (int) myDoc[0];
        byte[] intest = Arrays.copyOfRange(myDoc, 1, size_intest + 1);
        String[] intestVect = utility.intestToStringArray(intest, 5);
        byte[] hi = Arrays.copyOfRange(myDoc, size_intest + 1, size_intest + 1 + 32);
        byte[] sequenceMerkle = Arrays.copyOfRange(myDoc, size_intest + 1 + 32, size_intest + 1 + 32 + 99);
        byte[] sh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99, size_intest + 1 + 32 + 99 + 32);
        byte[] preSh = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32, size_intest + 1 + 32 + 99 + 32 + 32);
        byte[] sign = Arrays.copyOfRange(myDoc, size_intest + 1 + 32 + 99 + 32 + 32, myDoc.length);
        byte[] arrayToVerify = utility.arrayToVerify(intest, hi, sequenceMerkle, sh, preSh);
        byte[] rootHash = this.constructRoot(hi, sequenceMerkle);
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //creo una istanza di SHA

        if (utility.verifySign(arrayToVerify, sign, tsaKey, intestVect[3])) {
            if (online) {
                check = checkOnline();
            } else {
                sha.update(utility.concatByte(preSh, rootHash));
                if (sh == sha.digest()) {
                    check = true;
                }

            }
        } else {
            check = false;
        }
        return check;

    }

    private byte[] constructRoot(byte[] hi, byte[] sequence) throws IOException, NoSuchAlgorithmException {

        byte firstFusion = sequence[0];
        byte[] brotherLeaf = Arrays.copyOfRange(sequence, 1, 33);
        byte secondFusion = sequence[33];
        byte[] firstBrother = Arrays.copyOfRange(sequence, 34, 67);
        byte thirdFusion = sequence[67];
        byte[] lastBrother = Arrays.copyOfRange(sequence, 68, sequence.length);
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
            sha.update(utility.concatByte(lastBrother, root));
            root = sha.digest();
        }
        return root;
    }



    private boolean checkOnline() throws IOException {

        return true;
    }

}
