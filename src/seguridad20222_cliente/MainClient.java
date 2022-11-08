package seguridad20222_cliente;

import seguridad20222_servidor.MainServer;

import java.io.IOException;
import java.net.Socket;
import java.util.Arrays;
import java.util.Scanner;

public class MainClient {

    private static final String ID = "Main Client: ";
    private static Socket socket;

    public static void main(String[] args) throws IOException {
        int numberPetitions = 1;//intput();
        socket = new Socket("localhost", 4030);
        for (int i = 1; i <= numberPetitions; i++) {
            ThreadClient client = new ThreadClient(socket, i, "cliente"+i, i*10);
            new Thread(client).start();
        }
    }

    private static int intput() {
        try (Scanner sc = new Scanner(System.in);) {
            return sc.nextInt();
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    public static void secureinit() {

    }
}
