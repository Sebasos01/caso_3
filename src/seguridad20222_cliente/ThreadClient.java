package seguridad20222_cliente;

import seguridad20222_servidor.MainServer;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ThreadClient implements Runnable {

    private final Socket socket;
    private final PrintWriter output;
    private final Scanner input;

    private final int id, idPaquete;
    private final String name;

    public ThreadClient(String server, int port, int idThread, String nameClient, int idPack) throws IOException {
        id = idThread;
        name = nameClient;
        idPaquete = idPack;
        socket = new Socket(server, port);
        output = new PrintWriter(socket.getOutputStream(), true);
        input = new Scanner(new InputStreamReader(socket.getInputStream()));
    }

    @Override public void run() {
        try {
            String msg = id + "_" + name + "_" + idPaquete;
            MainClient.log("Inicio", msg);

            String cyphered, decyphered;

            /*Start*/
            MainClient.secureinit();


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String parse(byte[] arr) {
        return new String(arr);
    }

    private byte[] parse(String str) {
        return str.getBytes();
    }
}
