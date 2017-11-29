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
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author francesco
 */
public class KeyRing implements Serializable {

    private class WrapperSimmetric implements Serializable {

        private Map<String, SecretKey> dict_byte;

        private WrapperSimmetric() {
            this.dict_byte = new HashMap<String, SecretKey>();

        }

        private SecretKey get(String id) {
            return this.dict_byte.get(id);
        }

        private void add(String id, SecretKey k) {
            this.dict_byte.put(id, k);
        }

    }

    private class WrapperAsimmetric implements Serializable {

        private Map<String, KeyPair> dict_byte;

        private WrapperAsimmetric() {
            this.dict_byte = new HashMap<String, KeyPair>();

        }

        private KeyPair get(String id) {
            return this.dict_byte.get(id);
        }

        private void add(String id, KeyPair k) {
            this.dict_byte.put(id, k);
        }

    }

    private class WrapperPublic implements Serializable {

        private Map<String, PublicKey> dict_byte;

        private WrapperPublic() {
            this.dict_byte = new HashMap<String, PublicKey>();

        }

        private PublicKey get(String id) {
            return this.dict_byte.get(id);
        }

        private void add(String id, PublicKey k) {
            this.dict_byte.put(id, k);
        }

    }

    private Map<String, WrapperAsimmetric> dict_asimmetric_key;
    private Map<String, WrapperAsimmetric> dict_signature;
    private Map<String, String> dict_pass_web;
    private Map<String, WrapperSimmetric> dict_simmetric_key;
    private Map<String, WrapperPublic> dict_public_key;

    private byte[] salt;

    private int magicNumber = 65536;

    private SecureRandom random;

    public KeyRing() {

        this.dict_signature = new HashMap<String, WrapperAsimmetric>(); //ok
        this.dict_asimmetric_key = new HashMap<String, WrapperAsimmetric>(); //ok
        this.dict_pass_web = new HashMap<String, String>();
        this.dict_simmetric_key = new HashMap<String, WrapperSimmetric>(); //Wrapper
        this.dict_public_key = new HashMap<String, WrapperPublic>();
        this.random = new SecureRandom();
        this.salt = new byte[32];
        random.nextBytes(salt);

    }

    public PublicKey getPublicKey(String type, String id) {

        if (this.dict_public_key.containsKey(type)) {
            WrapperPublic w = this.dict_public_key.get(type);
            return w.get(id);

        } else {
            return null;
        }

    }

    public void addPublicKey(String type, String id, PublicKey k) {

        if (this.dict_public_key.containsKey(type)) {
            this.dict_public_key.get(type).add(id, k);

        } else {

            WrapperPublic w = new WrapperPublic();
            w.add(id, k);
            this.dict_public_key.put(type, w);

        }
    }

    public PublicKey getMyPublicSignature(String type, String id) {

        if (this.dict_signature.containsKey(type)) {
            WrapperAsimmetric w = this.dict_signature.get(type);
            return w.get(id).getPublic();

        } else {
            return null;
        }

    }

    public PrivateKey getMyPrivateSignature(String type, String id) {

        if (this.dict_signature.containsKey(type)) {
            WrapperAsimmetric w = this.dict_signature.get(type);
            return w.get(id).getPrivate();

        } else {
            return null;
        }

    }

    public PublicKey getMyPublicAsimmetric(String type, String id) {

        if (this.dict_asimmetric_key.containsKey(type)) {
            WrapperAsimmetric w = this.dict_asimmetric_key.get(type);
            return w.get(id).getPublic();

        } else {
            return null;
        }

    }

    public PrivateKey getMyPrivateAsimmetric(String type, String id) {

        if (this.dict_asimmetric_key.containsKey(type)) {
            WrapperAsimmetric w = this.dict_asimmetric_key.get(type);
            return w.get(id).getPrivate();

        } else {
            return null;
        }

    }

    public void addKeyPairSignature(String type, String id, KeyPair kp) {

        if (this.dict_signature.containsKey(type)) {
            this.dict_signature.get(type).add(id, kp);

        } else {

            WrapperAsimmetric w = new WrapperAsimmetric();
            w.add(id, kp);
            this.dict_signature.put(type, w);

        }
    }

    public void addKeyPairAsimmetric(String type, String id, KeyPair kp) {

        if (this.dict_asimmetric_key.containsKey(type)) {
            this.dict_asimmetric_key.get(type).add(id, kp);

        } else {

            WrapperAsimmetric w = new WrapperAsimmetric();
            w.add(id, kp);
            this.dict_asimmetric_key.put(type, w);

        }
    }

    public String getPassWeb(String id) {
        String pass = this.dict_pass_web.get(id);
        return pass;
    }

    public void addPassWeb(String id, String pass) {
        this.dict_pass_web.put(id, pass);
    }

    public SecretKey getSimmetric(String type, String id) {

        if (this.dict_simmetric_key.containsKey(type)) {
            WrapperSimmetric w = this.dict_simmetric_key.get(type);
            return w.get(id);

        } else {
            return null;
        }

    }

    public void addSimmetric(String type, String id, SecretKey k) {

        if (this.dict_simmetric_key.containsKey(type)) {
            this.dict_simmetric_key.get(type).add(id, k);

        } else {

            WrapperSimmetric w = new WrapperSimmetric();
            w.add(id, k);
            this.dict_simmetric_key.put(type, w);

        }
    }

    public void loadKeyRing(String path, String password) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        KeyRing kr = new KeyRing();
        byte cipherFile[];
        cipherFile = utility.loadFile(path);
        byte[] IV = new byte[16];

        for (int i = 0; i < 16; i++) {
            IV[i] = cipherFile[i];
        }
        int j = 0;
        for (int i = 16; i < this.salt.length + 16; i++) {
            this.salt[j] = cipherFile[i];
            j++;
        }

        IvParameterSpec iv = new IvParameterSpec(IV);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), this.salt, this.magicNumber, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte cipherWallet[] = new byte[cipherFile.length - this.salt.length - 16];

        for (int i = this.salt.length + 16; i < cipherFile.length; i++) {
            cipherWallet[i - this.salt.length - 16] = cipherFile[i];
        }

        byte clearWallet[] = cipher.doFinal(cipherWallet);
        ByteArrayInputStream bis = new ByteArrayInputStream(clearWallet);
        ObjectInput in = null;
        in = new ObjectInputStream(bis);
        kr = (KeyRing) in.readObject();

        this.dict_asimmetric_key = kr.dict_asimmetric_key;
        this.dict_public_key = kr.dict_public_key;
        this.dict_signature = kr.dict_signature;
        this.dict_pass_web = kr.dict_pass_web;
        this.dict_simmetric_key = kr.dict_simmetric_key;

    }

    public void SaveKeyRing(String password, String path, String label) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), this.salt, this.magicNumber, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] IV = cipher.getIV();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(this);
        out.flush();
        byte[] byteClass = bos.toByteArray();
        byte[] byteCipher = cipher.doFinal(byteClass);
        out.close();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(IV);
        outputStream.write(this.salt);
        outputStream.write(byteCipher);

        byte complete[] = outputStream.toByteArray();
        outputStream.close();
        utility.writeFile(path + "/" + label + ".w", complete);

    }

}
