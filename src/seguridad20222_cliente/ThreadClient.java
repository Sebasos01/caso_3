package seguridad20222_cliente;

import utility.Log;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ThreadClient implements Runnable {

    private final Socket socket;
    private final PrintWriter output;
    private final Scanner input, userInput;

    private final int id, idPaquete;
    private final String name;

    public ThreadClient(String server, int port, int idThread, String nameClient, int idPack) throws IOException {
        id = idThread;
        name = nameClient;
        idPaquete = idPack;
        socket = new Socket(server, port);
        output = new PrintWriter(socket.getOutputStream(), true);
        input = new Scanner(new InputStreamReader(socket.getInputStream()));
        userInput = new Scanner(System.in);
    }

    @Override public void run() {
        try {
            execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void execute() throws IOException {
        try {
            String msg = id + "_" + name + "_" + idPaquete;
            Log.log("Inicio ", msg);
            ProtocolClient.procesate(userInput, input, output);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            socket.close();
        }
    }
}
