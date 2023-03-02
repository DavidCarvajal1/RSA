package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class Encriptar {
    public static void main(String[] args) {
        encriptarConClavePrivadaEmisor();
        encriptarConClavePublicaReceptor();
    }

    private static void encriptarConClavePrivadaEmisor() {
        try {
            //Obtenemos la clave privada del emisor
            PrivateKey clavePrivada = KeysManager.getClavePrivada(KeysManager.PRIVATE_KEY_FILE_EMISOR);
            //Leemos el fichero
            String texto = ManejadoraFicheros.leerFichero();

            byte[] textoACifrar = texto.getBytes();

            //Ciframos con la clave privada del emisor

            byte[] textoCifrado = cifrarContenido(textoACifrar, clavePrivada, ((RSAPrivateKey) clavePrivada).getModulus());

            ManejadoraFicheros.escribirEnFichero(Base64.getEncoder().encodeToString(textoCifrado));


        }  catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo seleccionado no existe");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.err.println("No existe el padding seleccionado");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("La clave introducida no es válida");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.err.println("El tamaño del bloque utilizado no es correcto");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.err.println("El padding utilizado es erróneo");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encriptarConClavePublicaReceptor() {
        try {
            //Obtenemos la clave privada del emisor
            PublicKey publicKey = KeysManager.getClavePublica(KeysManager.PUBLIC_KEY_FILE_RECEPTOR);
            //Leemos el fichero
            String texto = ManejadoraFicheros.leerFichero();

            byte[] textoACifrar = texto.getBytes();

            //Ciframos con la clave privada del emisor

            byte[] textoCifrado = cifrarContenido(textoACifrar, publicKey, ((RSAPublicKey) publicKey).getModulus());

            ManejadoraFicheros.escribirEnFichero(Base64.getEncoder().encodeToString(textoCifrado));


        }  catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo seleccionado no existe");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.err.println("No existe el padding seleccionado");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("La clave introducida no es válida");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.err.println("El tamaño del bloque utilizado no es correcto");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.err.println("El padding utilizado es erróneo");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] cifrarContenido(byte[] contenido, Key clave, BigInteger tamanio) throws Exception {
        // Crear objeto Cipher
        Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // Inicializar cifrador en modo cifrado con la clave proporcionada
        cifrador.init(Cipher.ENCRYPT_MODE, clave);

        // Calcular tamaño del bloque
        int tamanoBloque = (tamanio.bitLength() + 7) / 8 - 11;

        // Inicializar buffer de salida
        ByteArrayOutputStream bufferSalida = new ByteArrayOutputStream();

        // Cifrar el contenido en bloques
        int offset = 0;
        while (offset < contenido.length) {
            int tamanoBloqueActual = Math.min(tamanoBloque, contenido.length - offset);
            byte[] bloqueCifrado = cifrador.doFinal(contenido, offset, tamanoBloqueActual);
            bufferSalida.write(bloqueCifrado);
            offset += tamanoBloqueActual;
        }

        // Devolver contenido cifrado completo
        return bufferSalida.toByteArray();
    }

}

