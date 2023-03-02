package com.company;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeysManager {

    public static final String PUBLIC_KEY_FILE_EMISOR = "public_key_emisor.key";
    public static final String PRIVATE_KEY_FILE_EMISOR = "private_key_emisor.key";
    public static final String PUBLIC_KEY_FILE_RECEPTOR = "public_key_receptor.key";
    public static final String PRIVATE_KEY_FILE_RECEPTOR = "private_key_receptor.key";

    public static KeyPair generarClaves() {
        KeyPairGenerator generador;
        KeyPair claves = null;
        try {
            generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(2048);
            claves = generador.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("No existe el algoritmo especificado");
            e.printStackTrace();
        }

        return claves;
    }

    public static void guardarClaves(KeyPair claves,String public_key_file,String private_key_file) {
        FileOutputStream fos;
        try {
            fos = new FileOutputStream(public_key_file);
            fos.write(claves.getPublic().getEncoded());
            fos.close();

            fos = new FileOutputStream(private_key_file);
            fos.write(claves.getPrivate().getEncoded());
            fos.close();
        } catch (FileNotFoundException e) {
            System.err.println("No se encuentra el fichero.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Se ha producido un error durante la escritura en el fichero.");
            e.printStackTrace();
        }

    }

    public static PublicKey getClavePublica(String public_key_file) {
        File ficheroClavePublica = new File(public_key_file);
        PublicKey clavePublica = null;
        try {

            byte[] bytesClavePublica = Files.readAllBytes(ficheroClavePublica.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytesClavePublica);
            clavePublica = keyFactory.generatePublic(publicKeySpec);

        } catch (IOException e) {
            System.err.println("Se ha producido en la lectura del fichero");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("No existe el algoritmo especificado");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("La clave indicada no es válida");
            e.printStackTrace();
        }
        return clavePublica;
    }

    public static PrivateKey getClavePrivada(String private_key_file) {
        File ficheroClavePrivada = new File(private_key_file);
        PrivateKey clavePrivada = null;
        try {

            byte[] bytesClavePrivada = Files.readAllBytes(ficheroClavePrivada.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytesClavePrivada);
            clavePrivada = keyFactory.generatePrivate(privateKeySpec);

        } catch (IOException e) {
            System.err.println("Se ha producido en la lectura del fichero");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("No existe el algoritmo especificado");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("La clave indicada no es válida");
            e.printStackTrace();
        }
        return clavePrivada;
    }

    public static void main(String[] args) {
        //Creamos las claves del emisor
        KeyPair claves = generarClaves();
        guardarClaves(claves,PUBLIC_KEY_FILE_EMISOR,PRIVATE_KEY_FILE_EMISOR);
        //Creamos las claves del receptor
        claves= generarClaves();
        guardarClaves(claves,PUBLIC_KEY_FILE_RECEPTOR,PRIVATE_KEY_FILE_RECEPTOR);
    }
}
