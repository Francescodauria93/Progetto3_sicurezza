/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author f.did
 */
public class KeyRing implements Serializable{

    private class Wrapper implements Serializable {

        byte[] item_one_1024, item_two_1024 , item_one_2048, item_two_2048;

        public Wrapper(byte[] cK, byte[] sK , byte[] cK2, byte[] sK2) {

            this.item_one_1024 = cK;
            this.item_two_1024 = sK;
            
            this.item_one_2048 = cK2;
            this.item_two_2048 = sK2;

        }

        public byte[] getOne_1024() {
            return this.item_one_1024;
        }

        public byte[] getTwo_1024() {
            return this.item_two_1024;
        }
        
        public byte[] getOne_2048() {
            return this.item_one_2048;
        }

        public byte[] getTwo_2048() {
            return this.item_two_2048;
        }

    }

    private Map<String, Wrapper> wallet;

    private byte[] privateRsa_1024;

    private byte[] privateDsa_1024;
    
    private byte[] privateRsa_2048;

    private byte[] privateDsa_2048;

    private byte[] salt;

    private int magicNumber = 65536;

    private SecureRandom random;

    public KeyRing() {

        this.wallet = new HashMap<String, Wrapper>();
        this.random = new SecureRandom();
        this.salt = new byte[16];
        random.nextBytes(salt);

    }

    public PublicKey getPublicSign(String id,String num) throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        byte []publicK = null;
        
        if(num.equals("1024")){
        publicK = wallet.get(id).getTwo_1024();
        }else{
            publicK = wallet.get(id).getTwo_2048();
        }
        
        KeyFactory kf = KeyFactory.getInstance("DSA");
        return kf.generatePublic(new X509EncodedKeySpec(publicK));

    }

    public PublicKey getPublicRsa(String id,String num) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] publicK =null;
        
        if(num.equals("1024")){
        publicK = wallet.get(id).getOne_1024();
        }else{
            publicK = wallet.get(id).getOne_2048();
        }
                
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(publicK));

    }

    public PrivateKey getPrivateRsa(String num) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] privateK =null;
        if(num.equals("1024")){
             privateK = this.privateRsa_1024;
        }else{
            privateK = this.privateRsa_2048;
        }
        
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(privateK));

    }

    public PrivateKey getPrivateDsa(String num) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] privateK = null;
        if(num.equals("1024")){
             privateK = this.privateDsa_1024;
        }else{
            privateK = this.privateDsa_2048;
        }
        
        KeyFactory kf = KeyFactory.getInstance("DSA");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(privateK));

    }

    public void setId(String id, PublicKey rsa1024, PublicKey sign1024, PublicKey rsa2048, PublicKey sign2048) {

        Wrapper w = new Wrapper(rsa1024.getEncoded(), sign1024.getEncoded(),rsa2048.getEncoded(), sign2048.getEncoded());

        this.wallet.put(id, w);

    }

    public void setPrivateRsa(PrivateKey rsa , String num) {
        
        
        if(num.equals("1024")){
            this.privateRsa_1024 = rsa.getEncoded();
        }else{
            this.privateRsa_2048 = rsa.getEncoded();
        }

        

    }

    public void setPrivateDsa(PrivateKey dsa,String num) {

        if(num.equals("1024")){
            this.privateDsa_1024 = dsa.getEncoded();
        }else{
            this.privateDsa_2048 = dsa.getEncoded();
        }

    }

    private Map<String, Wrapper> getThisWallet() {
        return this.wallet;
    }

    private byte[] getThisPrRsa(String num) {
        if(num.equals("1024")){
             return this.privateRsa_1024;
        }else{
             return this.privateRsa_2048;
        }

       
    }

    private byte[] getThisPrDsa(String num) {
        if(num.equals("1024")){
             return this.privateDsa_1024;
        }else{
             return this.privateDsa_2048;
        }
    }

    public void loadWallet(String path ,String password) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        KeyRing w = new KeyRing();
        byte cipherFile[];
        cipherFile = fileUtility.loadFile(path);
        
        for(int i=0 ;i<this.salt.length;i++){
            this.salt[i]=cipherFile[i];
        }
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), this.salt, this.magicNumber, 128);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") ;
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        
        byte cipherWallet[] = new byte[cipherFile.length - this.salt.length] ;
        
        for(int i=this.salt.length ;i<cipherFile.length;i++){
            cipherWallet[i-this.salt.length]=cipherFile[i];
        }
        
        byte clearWallet[] =  cipher.doFinal(cipherWallet) ;
        ByteArrayInputStream bis = new ByteArrayInputStream(clearWallet);
        ObjectInput in = null;
        in = new ObjectInputStream(bis);
        w = (KeyRing)in.readObject(); 
        
        this.wallet = w.getThisWallet();
        this.privateDsa_1024 = w.getThisPrDsa("1024");
        this.privateRsa_1024 = w.getThisPrRsa("1024");
        this.privateDsa_2048 = w.getThisPrDsa("2048");
        this.privateRsa_2048 = w.getThisPrRsa("2048");

    }

    public void SaveWallet(String password,String path, String label) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), this.salt, this.magicNumber, 128);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") ;
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out  = new ObjectOutputStream(bos);   
        out.writeObject(this);
        out.flush();
        byte[] byteClass = bos.toByteArray();
        byte[] byteCipher = cipher.doFinal(byteClass);
        out.close();
        
              
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(this.salt);
        outputStream.write(byteCipher);

        byte complete[] = outputStream.toByteArray();
        outputStream.close();
        fileUtility.writeFile(path+label+".w",complete );
   

    }

}
