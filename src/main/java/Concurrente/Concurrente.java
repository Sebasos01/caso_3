package Concurrente;

import Util.FuncionesDeSeguridad;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Concurrente extends Thread {
    protected final Socket SOCKET;
    protected final int ID;
    protected final String MENSAJE_DEFECTO;
    protected final FuncionesDeSeguridad FNS_SEGURIDAD;
    protected final String MENSAJE_OK = "OK";
    protected final String MENSAJE_ERROR = "ERROR";
    protected final String INICIO_SEGURO = "SECURE_INIT";
    protected PrintWriter canalEscritura;
    protected BufferedReader canalLectura;
    protected SecretKey llaveCifrado;
    protected SecretKey llaveHMAC;

    public Concurrente(Socket socket, int id, String nombre) {
        SOCKET = socket;
        ID = id;
        MENSAJE_DEFECTO = String.format("%s %d: ", nombre, ID);
        FNS_SEGURIDAD = new FuncionesDeSeguridad();
    }

    protected byte[] hexaStr2byte(String ss) {
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length() / 2];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }

    protected String byte2HexaStr(byte[] b) {
        // Encapsulamiento con hexadecimales
        StringBuilder texto = new StringBuilder();
        for (byte value : b) {
            String g = Integer.toHexString(((char) value) & 0x00ff);
            texto.append(g.length() == 1 ? "0" : "").append(g);
        }
        return texto.toString();
    }

    protected String generarIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return byte2HexaStr(iv);
    }

    protected IvParameterSpec hexaStr2Iv(String iv) {
        byte[] iv1 = hexaStr2byte(iv);
        return new IvParameterSpec(iv1);
    }

    protected BigInteger calcularY(BigInteger base, BigInteger exponente, BigInteger modulo) {
        return base.modPow(exponente, modulo);
    }

    protected BigInteger generarX() {
        SecureRandom r = new SecureRandom();
        int x = Math.abs(r.nextInt());
        return BigInteger.valueOf(x);
    }

    protected void generarCanalesComunicacion() throws IOException {
        canalEscritura = new PrintWriter(SOCKET.getOutputStream(), true);
        canalLectura = new BufferedReader(new InputStreamReader(SOCKET.getInputStream()));
    }

    protected void cerrarCanalesComunicacion() throws IOException {
        canalEscritura.close();
        canalLectura.close();
    }

    protected BigInteger calcularLlaveMaestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
        return base.modPow(exponente, modulo);
    }

    protected void imprimirInfo(String info) {
        System.out.printf("%s%s%n", MENSAJE_DEFECTO, info);
    }

    protected void imprimirError(String error) {
        System.err.printf("%s%s%n", MENSAJE_DEFECTO, error);
    }

    protected static class Pair<T, V> {
        public T p;
        public V g;

        public Pair(T p, V g) {
            this.p = p;
            this.g = g;
        }
    }

    protected static class Tripla<T, V, L> {
        public T a;
        public V b;
        public L c;

        public Tripla(T a, V b, L c) {
            this.a = a;
            this.b = b;
            this.c = c;
        }
    }

}