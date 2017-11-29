import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CifrareRSA {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
 		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024, new SecureRandom());
		KeyPair userKey = keyPairGenerator.generateKeyPair();
		
		PrivateKey userKeyPr = userKey.getPrivate();
		PublicKey userKeyPub = userKey.getPublic();

		byte privata[] = userKeyPr.getEncoded();
		byte pubblica[] = userKeyPub.getEncoded();
		
		System.out.println("Algoritmo: " +userKeyPr.getAlgorithm() );
		System.out.println("Formato chiave privata:    " + userKeyPr.getFormat());
		System.out.println("Formato chiave pubblica:   " + userKeyPub.getFormat());

		String encodedSecKey = Base64.getEncoder().encodeToString(privata);
		System.out.println("Privata  Base64: " + encodedSecKey);
		String encodedPubKey = Base64.getEncoder().encodeToString(pubblica);
		System.out.println("Pubblica Base64: " + encodedPubKey);
				
		String testo ="Testo da cifrare"; //max 62 byte dipende dalla modalità OAEP
		System.out.println("Testo in chiaro: " + testo);
		
		Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		//Cipher c = Cipher.getInstance("RSA");

		//ECB non serve a niente, serve solo per compatibilità con il formato usato
		//per i cifrari a blocchi
		c.init(Cipher.ENCRYPT_MODE, userKeyPub);
		byte[] plaintext = testo.getBytes("UTF8");
		byte[] ciphertext  = c.doFinal(plaintext);
		System.out.println("Lunghezza testo cifrato: " + ciphertext.length);
		System.out.println("Testo cifrato: " + Base64.getEncoder().encodeToString(ciphertext));
	
		//Estrazione paramentri da chiavi RSA
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec priv = kf.getKeySpec(userKeyPr, RSAPrivateKeySpec.class);
		BigInteger modulo = priv.getModulus();
		BigInteger esponenteD = priv.getPrivateExponent();
		RSAPublicKeySpec pub = kf.getKeySpec(userKeyPub, RSAPublicKeySpec.class);
		BigInteger esponenteE = pub.getPublicExponent();
		System.out.println("Modulo:             " + modulo);
		System.out.println("Lunghezza modulo:   " + modulo.toByteArray().length);
		System.out.println("Esponente privato:  " + esponenteD);
		System.out.println("Esponente pubblico: " + esponenteE);

		
		PublicKey publicKey = kf.generatePublic(new  X509EncodedKeySpec(pubblica));
		PrivateKey privateKey = kf.generatePrivate(new  PKCS8EncodedKeySpec(privata));
	
		c.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decodificato  = c.doFinal(ciphertext);
		System.out.println("Testo decifrato: " + new String(decodificato,"UTF8"));
				
	}

}
