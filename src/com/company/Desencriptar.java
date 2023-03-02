package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

public class Desencriptar {
    public static void main(String[] args) {

        desencriptarConClavePublicaEmisor();
        desencriptarConClavePrivadaReceptor();
    }
    private static void desencriptarConClavePublicaEmisor() {
        try {
            //Obtenemos la clave publica del emisor
            PublicKey publicKey = KeysManager.getClavePublica(KeysManager.PUBLIC_KEY_FILE_EMISOR);
            //Leemos el fichero
            String texto = ManejadoraFicheros.leerFichero();

            byte[] textoACifrar = Base64.getDecoder().decode(texto);

            //Desciframos con la clave privada del emisor

            byte[] textoCifrado = descifrarContenido(textoACifrar, publicKey, ((RSAPublicKey) publicKey).getModulus());

            ManejadoraFicheros.escribirEnFichero(new String(textoCifrado));

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

    private static void desencriptarConClavePrivadaReceptor(){
        try {

            //Obtenemos la clave privada del receptor
            PrivateKey privateKey = KeysManager.getClavePrivada(KeysManager.PRIVATE_KEY_FILE_RECEPTOR);
            //Leemos el fichero
            String texto = ManejadoraFicheros.leerFichero();

            byte[] textoACifrar =  Base64.getDecoder().decode(texto);

            //Desciframos con la clave privada del emisor

            byte[] textoCifrado = descifrarContenido(textoACifrar, privateKey, ((RSAPrivateKey) privateKey).getModulus());

            ManejadoraFicheros.escribirEnFichero(new String(textoCifrado));

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
    private static byte[] descifrarContenido(byte[] textoACifrar, Key clave, BigInteger tamanio) throws Exception{
        // Crear objeto Cipher
        Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // Inicializar cifrador en modo cifrado con la clave proporcionada
        cifrador.init(Cipher.DECRYPT_MODE, clave);

        // Calcular tamaño del bloque
        int tamanoBloque = (tamanio.bitLength() + 7) / 8;

        ByteArrayOutputStream bufferSalida = new ByteArrayOutputStream();

        //Desencriptamos con la clave del receptor
        int offset = 0;
        while (offset < textoACifrar.length) {
            int tamanoBloqueActual = Math.min(tamanoBloque, textoACifrar.length - offset);
            byte[] bloqueCifrado = Arrays.copyOfRange(textoACifrar, offset, offset + tamanoBloqueActual);
            byte[] archivoDescifrado = cifrador.doFinal(bloqueCifrado);

            bufferSalida.write(archivoDescifrado);
            offset += tamanoBloqueActual;
        }

        // Devolver contenido cifrado completo
        return bufferSalida.toByteArray();
    }
}
