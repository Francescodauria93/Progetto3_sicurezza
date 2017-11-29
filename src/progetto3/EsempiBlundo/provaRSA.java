import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class provaRSA {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024, new SecureRandom());
		KeyPair userKey = keyPairGenerator.generateKeyPair();
		PrivateKey userKeyPr = userKey.getPrivate();
		PublicKey userKeyPub = userKey.getPublic();
		Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		c.init(Cipher.ENCRYPT_MODE, userKeyPub);
		String testo ="01234567890123456789012345678901234567890123456789012345678901"
				     + "01234567890123456789012345678901234567890123456789012345678901"
				     + "01234567890123456789012"; 
		System.out.println("Lunghezza testo: " + testo.length());
		byte[] plaintext = testo.getBytes("UTF8");
		byte[] ciphertext = null;
		byte[] toEncode   = new byte[62]; //max 62 byte dipende da OAEP

		for(int i=0; i< plaintext.length/62; i++){
			System.arraycopy(plaintext, 
	                 i*62,
	                 toEncode,
	                 0,
	                 62);

			ciphertext = c.doFinal(toEncode);
			System.out.print("Testo cifrato blocco " + i + ": ");
			System.out.println(Base64.getEncoder().encodeToString(ciphertext));

		}
		if(plaintext.length % 62 > 0) {
			System.arraycopy(plaintext, 
					         (plaintext.length / 62) * 62, 
					         toEncode, 0, 
					         plaintext.length % 62);
			ciphertext = c.doFinal(toEncode);
			System.out.print("Testo cifrato blocco " + plaintext.length / 62 + ": ");
			System.out.println(Base64.getEncoder().encodeToString(ciphertext));
		}
	
	}
}
