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

public class AESCBC {
	public static void main(String[] args) {
		String text ="Proviamo a cifrare qualcosa in CBC mode";
		
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
		SecretKey secretKey = keyGenerator.generateKey();

		
	
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

/*
  //Costruiamo un generatore di IV
		SecureRandom random = new SecureRandom();
		byte IVBytes[] = new byte[16];
		random.nextBytes(IVBytes); 
		IvParameterSpec iv = new IvParameterSpec(IVBytes);
		
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
*/
		//IV generato dall'inizializzazione
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] ivN = cipher.getIV();
		
		System.out.print("\nIV: "); 
		for (int i=0;i<ivN.length;i++)
			System.out.print(ivN[i]+" ");
		
		String encodedIV = Base64.getEncoder().encodeToString(ivN);
		System.out.println("\nIV in Base64: " + encodedIV);
		
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


		
		
	}
}
