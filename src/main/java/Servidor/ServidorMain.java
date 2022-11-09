package Servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class ServidorMain {

    private static final String ID = "Servidor principal: ";
    private static final int puerto = 4030;
    private static final String NOMBRE_DEFAULT = "Servidor concurrente";

    public static void main(String[] args) throws IOException {
        System.out.println(ID + "iniciando servidor principal -> puerto: " + puerto);
        int idThread = 0;
        ServerSocket socketServidor = new ServerSocket(puerto);
        System.out.println(ID + "creando socket -> completado");
        String pruebas = "210";

        while (true) {
            Random random = new Random();
            int opcion = Math.abs(random.nextInt()) % 6;
            if (idThread % 3 == 0) {
                pruebas = switch (opcion) {
                    case 0 -> "012";
                    case 1 -> "021";
                    case 2 -> "102";
                    case 3 -> "120";
                    case 4 -> "201";
                    default -> "210";
                };
            }
            try {
                // Crea un delegado por cliente. Atiende por conexion.
                Socket socket = socketServidor.accept();
                System.out.println(ID + "Delegado " + idThread + " -> aceptando cliente -> completado");
                int pos = idThread % 3;
                int modo = pruebas.charAt(pos) - '0';
                ServidorThread delegado = new ServidorThread(modo, socket, idThread, NOMBRE_DEFAULT);
                idThread++;
                delegado.start();
            } catch (Exception e) {
                System.err.println(ID + " delegado " + idThread + ": aceptando cliente -> ERROR");
                e.printStackTrace();
            }
        }

    }

}