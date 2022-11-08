package seguridad20222_cliente;

import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;

public class MainClient {

    public static void main(String[] args) throws IOException {
        int numberPetitions = 1;//intput();
        Socket socket = new Socket("localhost", 4030);
        for (int i = 1; i <= numberPetitions; i++) {
            ThreadClient client = new ThreadClient(socket, i, "cliente" + i, i * 10);
            new Thread(client).start();
        }
    }

    private static int intput() {
        try (Scanner sc = new Scanner(System.in)) {
            return sc.nextInt();
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }
}
