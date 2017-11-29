import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PBKeyDerivation {

	public static void main(String[] args) {
		char[] password = {'s','i','c','u','r','e','z','z','a'};
		SecureRandom random = new SecureRandom();
		byte salt[] = new byte[3];
		random.nextBytes(salt);
		
		SecretKeyFactory factory=null;
		try {
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
		SecretKey tmp=null;
		try {
			tmp = factory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
		
		String text ="Ciao a tutti!";
		System.out.println("\nTEXT:\n"+text); 

		//Otteniamo un'istanza di Cipher
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES");
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
