package seguridad20222_cliente;

import seguridad20222_servidor.SecurityFunctions;
import seguridad20222_servidor.ThreadServer;
import utility.Log;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;

public class ThreadClient implements Runnable {

    private final Socket socket;
    private final DataOutputStream output;
    private final DataInputStream input;

    private final int id, idPaquete;
    private final String name;
    private final String identifier;

    public ThreadClient(Socket s, int idThread, String nameClient, int idPack) throws IOException {
        id = idThread;
        name = nameClient;
        idPaquete = idPack;
        socket = s;
        output = new DataOutputStream(socket.getOutputStream());
        input = new DataInputStream(socket.getInputStream());
        identifier = id + "_" + name + "_" + idPaquete;
    }

    @Override public void run() {
        try {
            /*
            Scanner sc = new Scanner(System.in);
            String val = sc.nextLine();
            execute(val);
            */
            execute(identifier);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void execute(String msg) throws IOException {
        try {
            String file, g, p, gx, f, master;
            BigInteger gVal, pVal, gXVal, gYVal, masterVal;
            PublicKey pk;
            byte[] signature;

            Log.log("Inicio ", identifier);

            /*Start*/
            output.writeUTF("");
            file = input.readUTF();
            g = input.readUTF();
            p = input.readUTF();
            gx = input.readUTF();
            f = input.readUTF();

            gVal = BigInteger.valueOf(Long.parseLong(g));
            pVal = BigInteger.valueOf(Long.parseLong(p));
            gXVal = BigInteger.valueOf(Long.parseLong(gx));

            signature = ThreadServer.str2byte(f);
            pk = SecurityFunctions.read_kplus(file, "delegate client " + id + ": ");
            /*Verification and return*/
            try {
                verify(signature, pk, g, p, gx);
            } catch (Exception e) {
                output.writeUTF("ERROR");
                throw e;
            }
            output.writeUTF("OK");

            /*gValY*/
            BigInteger bigy = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
            gYVal = G2Y(gVal, bigy, pVal);
            /*Sent g^y*/
            output.writeUTF(gYVal.toString());
            /*MasterKey*/
            masterVal = masterKey(gXVal, bigy, pVal);
            master = masterVal.toString();

            /*Generating SymmKey*/
            SecretKey sk_clt = SecurityFunctions.csk1(master);
            SecretKey sk_mac = SecurityFunctions.csk2(master);

            /*Generating IV*/
            byte[] iv1 = generateIvBytes();
            IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);

            /*El meollo1*/
            byte[] msgByte, kab1, kab2;
            msgByte = ThreadServer.str2byte(msg);

            kab1 = SecurityFunctions.senc(msgByte, sk_clt, ivSpec1, "Cliente");
            kab2 = SecurityFunctions.hmac(msgByte, sk_mac);

            /*El meollo2: Mas meollo que nunca*/
            String iv1STR, kab1STR, kab2STR;

            kab1STR = ThreadServer.byte2str(kab1);
            kab2STR = ThreadServer.byte2str(kab2);
            iv1STR = ThreadServer.byte2str(iv1);

            output.writeUTF(kab1STR);
            output.writeUTF(kab2STR);
            output.writeUTF(iv1STR);

            /*El meollo3: La venganza*/
            String response, consultSTR, hmacSTR, iv2STR;

            response = input.readUTF();
            consultSTR = input.readUTF();
            hmacSTR = input.readUTF();
            iv2STR = input.readUTF();

            if (response.equals("OK")) {
                byte[] consult, hmac, iv2, decyphered;

                consult = ThreadServer.str2byte(consultSTR);
                hmac = ThreadServer.str2byte(hmacSTR);

                iv2 = ThreadServer.str2byte(iv2STR);
                IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
                decyphered = SecurityFunctions.sdec(consult, sk_clt, ivSpec2);
                boolean verify = SecurityFunctions.checkInt(decyphered, sk_mac, hmac);

                if (verify) {
                    output.writeUTF("OK");
                } else output.writeUTF("ERROR");
            } else output.writeUTF("ERROR");


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            socket.close();
        }
    }

    private void verify(byte[] sign, PublicKey kplus, String g, String p, String common) throws Exception {
        String msg = g + "," + p + "," + common;
        SecurityFunctions.checkSignature(kplus, sign, msg);
    }

    private BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
        return base.modPow(exponente, modulo);
    }

    private BigInteger masterKey(BigInteger base, BigInteger exponente, BigInteger modulo) {
        return base.modPow(exponente, modulo);
    }

    private byte[] generateIvBytes() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}

/*
If you are reading this, have a great day :3

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣶⣿⣿⣷⣶⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣾⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⡟⠁⣰⣿⣿⣿⡿⠿⠻⠿⣿⣿⣿⣿⣧⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠏⠀⣴⣿⣿⣿⠉⠀⠀⠀⠀⠀⠈⢻⣿⣿⣇⠀⠀⠀
⠀⠀⠀⠀⢀⣠⣼⣿⣿⡏⠀⢠⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⡀⠀⠀
⠀⠀⠀⣰⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀
⠀⠀⢰⣿⣿⡿⣿⣿⣿⡇⠀⠘⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⢀⣸⣿⣿⣿⠁⠀⠀
⠀⠀⣿⣿⣿⠁⣿⣿⣿⡇⠀⠀⠻⣿⣿⣿⣷⣶⣶⣶⣶⣶⣿⣿⣿⣿⠃⠀⠀⠀
⠀⢰⣿⣿⡇⠀⣿⣿⣿⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀
⠀⢸⣿⣿⡇⠀⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠛⠉⢉⣿⣿⠀⠀⠀⠀⠀⠀
⠀⢸⣿⣿⣇⠀⣿⣿⣿⠀⠀⠀⠀⠀⢀⣤⣤⣤⡀⠀⠀⢸⣿⣿⣿⣷⣦⠀⠀⠀
⠀⠀⢻⣿⣿⣶⣿⣿⣿⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣦⡀⠀⠉⠉⠻⣿⣿⡇⠀⠀
⠀⠀⠀⠛⠿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠈⠹⣿⣿⣇⣀⠀⣠⣾⣿⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣦⣤⣤⣤⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⠿⠋⠉⠛⠋⠉⠉⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠁
 */
