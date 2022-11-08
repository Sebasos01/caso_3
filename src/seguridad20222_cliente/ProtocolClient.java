package seguridad20222_cliente;

import utility.Log;

import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ProtocolClient {
    public static void procesate(Scanner sIn, Scanner pIn, PrintWriter pOut) {
        /*Read From User*/
        String user = sIn.nextLine();
        //TODO: Cypher
        /*Send To Server*/
        pOut.println(user);
        /*Receive From Server*/
        String server = "";
        //TODO: Decypher
        if ((server = pIn.nextLine()) != null)
            Log.log("Respuesta: ", server);

    }
}
