package com.company;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class ManejadoraFicheros {
    public static String leerFichero () {
        String linea;
        StringBuilder texto= new StringBuilder();
        try(BufferedReader br = new BufferedReader(new FileReader("fichero.txt"))) {

            linea = br.readLine();
            while (linea != null) {
                texto.append(linea);
                linea = br.readLine();
            }

        } catch (FileNotFoundException e) {
            System.err.println("Fichero no encontrado.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Error leyendo el fichero.");
            e.printStackTrace();
        }
        return texto.toString();
    }
    public static void escribirEnFichero(String mensaje){
        try(BufferedWriter bw=new BufferedWriter(new FileWriter("fichero.txt"))){
                bw.write(mensaje);
                bw.newLine();
        }catch (IOException e){
            System.err.println("Error leyendo el fichero.");
            e.printStackTrace();
        }
    }
}
