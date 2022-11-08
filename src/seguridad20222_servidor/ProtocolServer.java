package seguridad20222_servidor;

import utility.Log;

import java.io.PrintWriter;
import java.util.Scanner;

public class ProtocolServer {
    public static void procesate(Scanner pIn, PrintWriter pOut){
        String input, output;
        input = pIn.nextLine();
        Log.log("Recibe ", input);
        //TODO: Cypher
        output = input;
        Log.log("Cifra ", input, "en ", output);

        pOut.println(output);
        Log.log("Envia ", output);
    }
}
