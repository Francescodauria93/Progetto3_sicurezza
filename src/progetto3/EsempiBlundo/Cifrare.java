import java.util.Base64;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class Cifrare {
	public static void main(String[] args) {

		//Otteniamo un'istanza di KeyGenerator
		KeyGenerator keyGenerator = null;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algoritmo non supportato");
		}

		System.out.println("-- KeyGenerator --");
		System.out.println("Provider: " + keyGenerator.getProvider());
		System.out.println("Algorithm: " + keyGenerator.getAlgorithm());



		//Inizializziamo il KeyGenerator
		keyGenerator.init(128, new SecureRandom());
		//keyGenerator.init(56);

		//Generiamo la chiave
		SecretKey secretKey = keyGenerator.generateKey();

		System.out.println("\n-- SecretKey --");
		System.out.println("String: " + secretKey.toString());
		System.out.println("Algorithm: " + secretKey.getAlgorithm());
		System.out.println("Format: " + secretKey.getFormat());
		System.out.println("Encoded: " + secretKey.getEncoded()); //byteArray

		//JAVA 8
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		System.out.println("Base64: " + encodedKey);

		String text ="Ciao a tutti!";
		//String text ="C";
		System.out.println("\nTEXT:\n"+text); 

		//Otteniamo un'istanza di Cipher
		Cipher cipher = null;
		try {
			//cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.out.println("Algoritmo o padding non supportato");
		}
		
		//Inizializziamo il cifrario
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		}

		//Convertiamo la stringa in byte specificando la codifica
		/**
		 * Evita problemi di conversione di array di byte a strina in caso 
		 * di mittente e destinatario su piattaforme differenti 
		 * (default: codifica della macchina sottostante)
		 */
		byte[] plaintext = null;
		try {
			plaintext = text.getBytes("UTF8");
		} catch (UnsupportedEncodingException e) {
			System.out.println("Codifica non supportata");
		}
		System.out.println("\nPLAINTEXT:"); 
		for (int i=0;i<plaintext.length;i++)
			System.out.print(plaintext[i]+" ");

		//Cifriamo
		byte[ ] ciphertext = null;
		try {
			ciphertext = cipher.doFinal(plaintext);
		} catch (IllegalBlockSizeException e) {
			System.out.println("Dimensione blocco errata");
		} catch (BadPaddingException e) {
			System.out.println("Padding errato");
		}

		System.out.println("\n\nCIPHERTEXT:"); 
		for (int i=0;i<ciphertext.length;i++)
			System.out.print(ciphertext[i]+" ");

		//Decifriamo
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		}

		byte[] decryptedText=null;
		try {
			decryptedText = cipher.doFinal(ciphertext);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Dimensione blocco errata oppure padding errato");
		}

		String output=null;
		try {
			output = new String(decryptedText,"UTF8");
		} catch (UnsupportedEncodingException e) {
			System.out.println("Codifica non supportata");
		} 
		System.out.println("\n\nDECRYPTED TEXT:\n"+output);

		
		
	}
}

