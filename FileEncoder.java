package sample;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * @author Bernardo Cabral
 *
 * Copyright (C) 2021 Bernardo Cabral - All Rights Reserved
 * You may use, distribute but not modify this code under the
 * terms of the Software license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the Software license with
 * this file. If not, please write to: bernardocabral2405@gmail.com
 **/
 
public class FileEncoder {
    private static final String ALGORITHM = "AES";
    private static final String[] DICTIONARY = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz","123456789"};
    private static final int KEY_LENGTH=16;
    private final List<String> files_encrypted= new ArrayList<>();
    private final List<byte[]> data_encrypted = new ArrayList<>();
    private Key secretKey;
    public FileEncoder(){
        secretKey= new SecretKeySpec(keyGen().getBytes(),ALGORITHM);
    }
    public String keyGen(){
        String control="";
        Random rand = new Random();
        for(int i =0;i<KEY_LENGTH;i++){
            String random = DICTIONARY[rand.nextInt(DICTIONARY.length)];
            control+=Character.toString(random.charAt(rand.nextInt(random.length())));
        }
        return control;
    }

    public Key getSecretKey() {
        return secretKey;
    }

    public void setSecretKey() {
        this.secretKey = new SecretKeySpec(keyGen().getBytes(),ALGORITHM);
    }

    public byte[] getFileBytes(String filePath) throws Exception{
        Path path = Paths.get(filePath);
        return Files.readAllBytes(path);
    }
    public void encrypt(String filePath) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] bytesEncrypted = cipher.doFinal(getFileBytes(filePath));
        saveFile(bytesEncrypted,filePath);
        files_encrypted.add(filePath);
        data_encrypted.add(bytesEncrypted);
        //cipher.init(Cipher.DECRYPT_MODE,secretKey);
    }
    public void saveFile(byte[] bytes,String filePath) throws Exception{
        File file = new File(filePath);
        OutputStream outputStream = new FileOutputStream(file);
        outputStream.write(bytes);
        outputStream.close();
    }
    public void decrypt() throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        int len = files_encrypted.size();
        for(int i=0;i<len;i++){
            byte[] bytesDecrypted= cipher.doFinal(data_encrypted.get(i));
            saveFile(bytesDecrypted,files_encrypted.get(i));
        }
    }
}
