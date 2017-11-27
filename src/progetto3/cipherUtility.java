/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author gruppo13
 */
public class cipherUtility {

    public static SecretKey SimmetricKeyGenerator(String type_cipher) {
        //return a key of differnt cipher, return null if cipher is not AES,DES,3-DES
        KeyGenerator keyGenerator = null;
        if (type_cipher.equals("AES") || type_cipher.equals("DES") || type_cipher.equals("DESede")) {
            try {
                keyGenerator = KeyGenerator.getInstance(type_cipher);

                if (type_cipher.equals("AES")) {
                    //Inizializziamo il KeyGenerator
                    keyGenerator.init(128, new SecureRandom());
                } else if (type_cipher.equals("DES")) {
                    //Inizializziamo il KeyGenerator
                    keyGenerator.init(56, new SecureRandom());
                } else if (type_cipher.equals("DESede")) {
                    //Inizializziamo il KeyGenerator
                    keyGenerator.init(168, new SecureRandom());
                }

            } catch (NoSuchAlgorithmException e) {
                System.out.println("Algoritmo non supportato");
            }
            return keyGenerator.generateKey();
        }
         else{
            return null;
        }
      
        }

    public static Cipher getIstanceSimmetricCipher(String type_cipher, String mode, String pad) {
        //Otteniamo un'istanza di Cipher
        Cipher cipher = null;
        boolean cond1 = type_cipher.equals("AES") || type_cipher.equals("DES") || type_cipher.equals("DESede");
        boolean cond2 = mode.equals("ECB") || mode.equals("CBC") || mode.equals("CFB");
        boolean cond3 = pad.equals("PKCS5Padding");
        if (cond1 && cond2 && cond3) {
            try {
                cipher = Cipher.getInstance(type_cipher + "/" + mode + "/" + pad);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                System.out.println("Algoritmo o padding non supportato");
            }
            return cipher;
        } else {
            return null;
        }
    }
    
    
    public static Cipher getIstanceAsimmetricCipher(String type_cipher, String mode, String pad) {
        //Otteniamo un'istanza di Cipher
        Cipher cipher = null;
        boolean cond1 = type_cipher.equals("RSA");
        boolean cond2 = mode.equals("ECB") || mode.equals("CBC") || mode.equals("CFB");
        boolean cond3 = pad.equals("PKCS1Padding") || pad.equals("OAEPPadding") || pad.equals("OAEPWithSHA-256AndMGF1Padding");
        if (cond1 && cond2 && cond3) {
            try {
                cipher = Cipher.getInstance(type_cipher + "/" + mode + "/" + pad);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                System.out.println("Algoritmo o padding non supportato");
            }
            return cipher;
        } else {
            return null;
        }
    }

    
    public static byte[] simmetricEncode(Cipher cipher, byte[] plaintext, SecretKey secretKey) throws InvalidAlgorithmParameterException {
   
            //Inizializziamo il cifrario in Ecrypt Mode
            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } catch (InvalidKeyException e) {
                System.out.println("Chiave non valida");
            }
        

        //Cifriamo
        byte[] ciphertext = null;
        try {
            ciphertext = cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException e) {
            System.out.println("Dimensione blocco errata");
        } catch (BadPaddingException e) {
            System.out.println("Padding errato");
        }
        return ciphertext;
    }
    

    public static byte[] simmetricDecode(Cipher cipher, byte[] ciphertext, SecretKey secretKey,byte[] ivN) throws InvalidAlgorithmParameterException {
        if (cipher.getAlgorithm().matches(".*(ECB).*")) {
            //Inizializziamo il cifrario in Decrypt Mode
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            } catch (InvalidKeyException e) {
                System.out.println("Chiave non valida");
            }
        } else {
                    
            IvParameterSpec iv = new IvParameterSpec(ivN);
            
            //Inizializziamo il cifrario in Decrypt Mode
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey,iv);
            } catch (InvalidKeyException e) {
                System.out.println("Chiave non valida");
            }
        }

        //Decifriamo
        byte[] decryptedText = null;
        try {
            decryptedText = cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Dimensione blocco errata oppure padding errato");
        }
        return decryptedText;
    }

    
    public static byte[] asimmetricEncode(Cipher cipher, byte[] plaintext, PublicKey secretKey) throws InvalidAlgorithmParameterException {
   
            //Inizializziamo il cifrario in Ecrypt Mode
            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } catch (InvalidKeyException e) {
                System.out.println("Chiave non valida");
            }
        

        //Cifriamo
        byte[] ciphertext = null;
        try {
            ciphertext = cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException e) {
            System.out.println("Dimensione blocco errata");
        } catch (BadPaddingException e) {
            System.out.println("Padding errato");
        }
        return ciphertext;
    }
    

    public static byte[] asimmetricDecode(Cipher cipher, byte[] ciphertext, PrivateKey secretKey) throws InvalidAlgorithmParameterException {
        if (cipher.getAlgorithm().matches(".*(ECB).*")) {
            //Inizializziamo il cifrario in Decrypt Mode
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            } catch (InvalidKeyException e) {
                System.out.println("Chiave non valida");
            }
        } else {
                    
            IvParameterSpec iv = new IvParameterSpec(cipher.getIV());
            //Inizializziamo il cifrario in Decrypt Mode
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey,iv);
            } catch (InvalidKeyException e) {
                System.out.println("Chiave non valida");
            }
        }

        //Decifriamo
        byte[] decryptedText = null;
        try {
            decryptedText = cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Dimensione blocco errata oppure padding errato");
        }
        return decryptedText;
    }

    public static byte[] sign(byte[] textToSign, PrivateKey userKeyPr, String keySize, String padding) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        if(padding.matches("SHA1withDSA") || padding.matches("SHA224withDSA") || padding.matches("SHA256withDSA")){
            Signature dsa = Signature.getInstance(padding);
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
