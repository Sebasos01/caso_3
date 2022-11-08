package seguridad20222_cliente;

import utility.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

public class ThreadClient implements Runnable {

    private final Socket socket;
    private final DataOutputStream output;
    private final DataInputStream input;
    //private final Scanner userInput;

    private final int id, idPaquete;
    private final String name;

    public ThreadClient(Socket s, int idThread, String nameClient, int idPack) throws IOException {
        id = idThread;
        name = nameClient;
        idPaquete = idPack;
        socket = s;
        output = new DataOutputStream(socket.getOutputStream());
        input = new DataInputStream(socket.getInputStream());
        //userInput = new Scanner(System.in);
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
            String g, p, gx, f, gy;
            BigInteger gVal, pVal, gXVal, gYVal;

            String msg = id + "_" + name + "_" + idPaquete;
            Log.log("Inicio ", msg);

            /*Start*/
            output.writeUTF("");
            g = input.readUTF();
            p = input.readUTF();
            gx = input.readUTF();
            f = input.readUTF();

            gVal = BigInteger.valueOf(Long.parseLong(g));
            pVal = BigInteger.valueOf(Long.parseLong(p));
            gXVal = BigInteger.valueOf(Long.parseLong(gx));

            /*Verification*/
            boolean v = verify(f, g, p, gx);
            /*Returning*/
            if (v) output.writeUTF("OK");
            else output.writeUTF("ERROR");
            /*gValY*/
            BigInteger bigy = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
            gYVal = G2Y(gVal, bigy, pVal);
            /*Sent g^y*/
            output.writeUTF(gYVal.toString());
            /*MasterKey*/


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            socket.close();
        }
    }

    private boolean verify(String sign, String gVal, String prime, String gValX) {
        return false;
    }

    private BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
        return base.modPow(exponente, modulo);
    }
}
