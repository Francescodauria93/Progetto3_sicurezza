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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;

public class firmaDSA {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException, InvalidKeySpecException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(1024, new SecureRandom());
		KeyPair userKey = keyPairGenerator.generateKeyPair();

		PrivateKey userKeyPr = userKey.getPrivate();
		PublicKey userKeyPub = userKey.getPublic();
		
		byte privata[] = userKeyPr.getEncoded();
		byte pubblica[] = userKeyPub.getEncoded();
		
		System.out.println("Algoritmo: " +userKeyPr.getAlgorithm() );
		System.out.println("Formato chiave privata:    " + userKeyPr.getFormat());
		System.out.println("Formato chiave pubblica:   " + userKeyPub.getFormat());

		String testo ="Testo da firmare molto lungo, più lungo di 160 bit."; 
		//String testo ="Testo da firmare."; 

		System.out.println("Testo: " + testo);
		
		Signature dsa = Signature.getInstance("SHA1withDSA");
		dsa.initSign(userKeyPr);
		dsa.update(testo.getBytes("UTF8"));
		byte[] firma = dsa.sign();
		System.out.println("Dimensione firma: " + firma.length);
		String encodedSig = Base64.getEncoder().encodeToString(firma);
		System.out.println("Firma in Base64: " + encodedSig);
		
		System.out.println("Firma in byte");
		for (int i=0;i<firma.length;i++)
			System.out.print(firma[i]+" ");
		
		dsa.initVerify(userKeyPub);
		dsa.update(testo.getBytes("UTF8"));
		System.out.println("Verifica firma: " + dsa.verify(firma));

		//Estrazione paramentri da chiavi DSA
		KeyFactory kf = KeyFactory.getInstance("DSA");
		DSAPrivateKeySpec priv = kf.getKeySpec(userKeyPr, DSAPrivateKeySpec.class);
		BigInteger base = priv.getG();
		BigInteger q = priv.getQ();
		BigInteger esponente = priv.getX();
		System.out.println("Base:      " + q);
		System.out.println("Primo q:   " + base);
		System.out.println(q.toByteArray().length);

		System.out.println("Esponente: " + esponente);
	}

}
