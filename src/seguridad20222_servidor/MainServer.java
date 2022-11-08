package seguridad20222_servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class MainServer {

    private static final String ID = "Main Server: ";
    private static final int puerto = 4030;
    private static ServerSocket ss;

    public static void main(String[] args) throws IOException {

        System.out.println(ID + "Starting main server. Port: " + puerto);

        int idThread = 0;
        ss = new ServerSocket(puerto);
        System.out.println(ID + "Creating socket: done");
        String options = "210";

        while (true) {
            Random optRandom = new Random();
            int opt = optRandom.nextInt() % 6;
            if (idThread % 3 == 0) {
                options = switch (opt) {
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
                //semaforo.acquire();
                Socket sc = ss.accept();
                System.out.println(ID + " delegate " + idThread + ": accepting client - done");
                int pos = idThread % 3;
                int mod = options.charAt(pos) - '0';
                ThreadServer d = new ThreadServer(sc, idThread, mod);
                idThread++;
                d.start();
            } catch (IOException e) {
                System.out.println(ID + " delegate " + idThread + ": accepting client - ERROR");
                e.printStackTrace();
            }
        }
    }
}
