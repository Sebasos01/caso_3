package Cliente;

import java.io.IOException;
import java.net.Socket;

public class ClienteMain {
    public final static int CASO = 4;
    private final static String HOST = "localhost";
    private final static int PUERTO = 4030;
    private static final String NOMBRE_DEFAULT = "Cliente concurrente";

    public static void main(String[] args) {
        for (int i = 1; i <= CASO; i++) {
            try {
                ClienteThread nuevoCliente = new ClienteThread(new Socket(HOST, PUERTO), i, NOMBRE_DEFAULT);
                nuevoCliente.start();
                System.out.printf("Cliente concurrente %d en ejecucion en el puerto %d%n", i, PUERTO);
            } catch (IOException e) {
                System.out.println("Error al clear cliente concurrente en interacion " + i);
                e.printStackTrace();
            }
        }
    }
}