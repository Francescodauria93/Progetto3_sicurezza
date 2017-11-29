import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class CifraturaMultipla {
	public static void main(String[] args) {
	//Otteniamo un'istanza di KeyGenerator
			KeyGenerator keyGenerator = null;
			try {
				keyGenerator = KeyGenerator.getInstance("DES");
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Algoritmo non supportato");
			}

			System.out.println("-- KeyGenerator --");
			System.out.println("Provider: " + keyGenerator.getProvider());
			System.out.println("Algorithm: " + keyGenerator.getAlgorithm());


			//keyGenerator.init(56);

			//Inizializziamo il KeyGenerator
			keyGenerator.init(56, new SecureRandom());

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
			System.out.println("\nTEXT:\n"+text); 

			//Otteniamo un'istanza di Cipher
			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				System.out.println("Algoritmo o padding non supportato");
			}
			
			System.out.println("toS: " +cipher.getParameters());

			//Inizializziamo il cifrario
			try {
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			} catch (InvalidKeyException e) {
				System.out.println("Chiave non valida");
			}

			//String s1 = "testo molto lungo da cifrare ";
			String s1 = "1234569890123456";

			String s2 = " testo aggiunto";
			
			try {
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			} catch (InvalidKeyException e) {
				System.out.println("Chiave non valida");
			}
			
			byte[] p1 = null, p2 = null;
			try {
				p1 = s1.getBytes("UTF8");
				p2 = s2.getBytes("UTF8");
			} catch (UnsupportedEncodingException e) {
				System.out.println("Codifica non supportata");
			}
			System.out.println("\nPLAINTEXT #1:"); 
			for (int i=0;i<p1.length;i++)
				System.out.print(p1[i]+" ");
			System.out.println("\nPLAINTEXT #2:"); 
			for (int i=0;i<p2.length;i++)
				System.out.print(p2[i]+" ");
			

			byte[ ] c1 = null, c2=null, c3=null;
			try {
				c1 = cipher.update(p1);
				c2 = cipher.update(p2);
				c3 = cipher.doFinal(); //svuota il buffer
			} catch (IllegalBlockSizeException e) {
				System.out.println("Dimensione blocco errata");
			} catch (BadPaddingException e) {
				System.out.println("Padding errato");
			}

			System.out.println("\nCIPHERTEXT 1:"); 
			for (int i=0;i<c1.length;i++)
				System.out.print(c1[i]+" ");
			System.out.println("\n\nCIPHERTEXT 2:"); 
			for (int i=0;i<c2.length;i++)
				System.out.print(c2[i]+" ");
			
			try {
				cipher.init(Cipher.DECRYPT_MODE, secretKey);
			} catch (InvalidKeyException e) {
				System.out.println("Chiave non valida");
			}
			
			//System.out.println("\n\nlunghezza buffer output: "+cipher.getOutputSize(c1.length));
			byte[] dT1=null, dT2=null, dT3=null;
			try {
				dT1 = cipher.update(c1);
				dT2 = cipher.update(c2);
				dT3 = cipher.doFinal(c3);//svuota il buffer
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				System.out.println("Dimensione blocco errata oppure padding errato");
			}
			String o1 = null, o2=null, o3=null;
			try {
				if(dT1!=null)
					o1 = new String(dT1,"UTF8");
				if(dT2!=null)
					o2 = new String(dT2,"UTF8");
				o3 = new String(dT3,"UTF8");
			} catch (UnsupportedEncodingException e) {
				System.out.println("Codifica non supportata");
			} 
			System.out.println("\n\nDECRYPTED TEXT 1:\n"+o1);
			System.out.println("\n\nDECRYPTED TEXT 2:\n"+o2);
			System.out.println("\n\nDECRYPTED TEXT 3:\n"+o3);

}
}

