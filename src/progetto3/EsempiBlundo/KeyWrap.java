import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KeyWrap {

	public static void main(String[] args) {
		//Otteniamo un'istanza di KeyGenerator
		KeyGenerator keyGenerator = null;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algoritmo non supportato");
		}

		//Inizializziamo il KeyGenerator
		keyGenerator.init(128, new SecureRandom());

		//Generiamo la chiave
		SecretKey secretKey1 = keyGenerator.generateKey();
		SecretKey secretKey2 = keyGenerator.generateKey();

		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.out.println("Algoritmo o padding non supportato");
		}
		
		//Inizializziamo il cifrario
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey1);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		}
		
		byte[ ] ciphertext = null;
		try {
			ciphertext = cipher.doFinal(secretKey2.getEncoded());
		} catch (IllegalBlockSizeException e) {
			System.out.println("Dimensione blocco errata");
		} catch (BadPaddingException e) {
			System.out.println("Padding errato");
		}

		System.out.println("CIPHERTEXT (ENCRYPTED KEY):"); 
		for (int i=0;i<ciphertext.length;i++)
			System.out.print(ciphertext[i]+" ");
		
		//Inizializziamo il cifrario in WRAP_MODE
		try {
			cipher.init(Cipher.WRAP_MODE, secretKey1);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		}

		byte[] wrappedKey = null;
		try {
			wrappedKey = cipher.wrap(secretKey2);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		} catch (IllegalBlockSizeException e) {
			System.out.println("Dimensione blocco errata");
		} 
		
		System.out.println("\n\nCIPHERTEXT (WRAPPED KEY):"); 
		for (int i=0;i<wrappedKey.length;i++)
			System.out.print(wrappedKey[i]+" ");
		
		//Inizializziamo il cifrario in UNWRAP_MODE
		try {
			cipher.init(Cipher.UNWRAP_MODE, secretKey1);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		}
	
		Key unwrappedKey = null;
		try {
			unwrappedKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algoritmo non supportato");
		}

		/*
		 * Usiamo il cifrario con la chiave unwrapped
		 */

		String text = "Prova di cifrautura con unwrapped key";
		System.out.println("\n\nTEXT:\n"+text);
		
		//Inizializziamo il cifrario
		try {
			cipher.init(Cipher.ENCRYPT_MODE, unwrappedKey);
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
		System.out.println("\n\nPLAINTEXT:"); 
		for (int i=0;i<plaintext.length;i++)
			System.out.print(plaintext[i]+" ");

		//Cifriamo
		ciphertext = null;
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
			cipher.init(Cipher.DECRYPT_MODE, unwrappedKey);
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
