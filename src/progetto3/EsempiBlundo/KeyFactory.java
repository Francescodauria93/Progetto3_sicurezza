import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class KeyFactory {

	public static void main(String[] args) {
		SecureRandom random = new SecureRandom();
		byte desKey[] = new byte[8];
		random.nextBytes(desKey); 
		
		DESKeySpec desKeySpec = null;
		try {
			 desKeySpec = new DESKeySpec(desKey);
		} catch (InvalidKeyException e) {
			System.out.println("Chiave non valida");
		}
		
		SecretKeyFactory factory = null;
		try {
			 factory = SecretKeyFactory.getInstance("DES");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algoritmo non supportato");
		}

		SecretKey  secretKey = null;
		try {
			 secretKey = factory.generateSecret(desKeySpec);
		} catch (InvalidKeySpecException e) {
			System.out.println("Chiave non valida");
		}
		
		byte [] encodedKey = secretKey.getEncoded();
		System.out.print("\nENCODED OPAQUE KEY: "); 
		for (int i=0;i<encodedKey.length;i++)
			System.out.print(encodedKey[i]+" ");

	
		//Da opaca (secretKey) a trasparente
		//Per cifrari a blocchi non c'è differenza
		DESKeySpec newDESKeySpec = null;
		try {
			newDESKeySpec = (DESKeySpec) factory.getKeySpec(secretKey, DESKeySpec.class);
		} catch (InvalidKeySpecException e1) {
			System.out.println("Chiave non valida");
		}
		
		
	    byte [] transparentDESKey = newDESKeySpec.getKey();
	
	    System.out.print("\nTRANSPARENT    KEY: "); 
		for (int i=0;i<transparentDESKey.length;i++)
			System.out.print(transparentDESKey[i]+" ");
		
		
		
		String text ="Esempio di KeyFactory";
		System.out.println("\n\nTEXT: "+text); 

		//Otteniamo un'istanza di Cipher
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
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
