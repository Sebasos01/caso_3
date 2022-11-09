package Util;

import Cliente.ClienteMain;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FuncionesDeSeguridad {
    private final String ALGORITMO_SIMETRICO = "AES/CBC/PKCS5Padding";
    private final String ALGORITMO_ASIMETRICO = "RSA";

    /** Metodo para escribir los datos y guardar el informe */
    public static void write(long l, String s, int i) {
        try (PrintWriter pw = new PrintWriter(
                new FileOutputStream("src/main/java/Util/dir/" + s + ClienteMain.CASO + ".dat", true))) {
            String msg = (double) i + "," + l + "\n";
            pw.append(msg);
            pw.flush();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] firmarConCifradoAsimetrico(PrivateKey privada, String mensaje) throws Exception {
        Signature firmador = Signature.getInstance("SHA256withRSA");
        firmador.initSign(privada);
        firmador.update(mensaje.getBytes(StandardCharsets.UTF_8));
        return firmador.sign();
    }

    public boolean verificarFirma(PublicKey publica, byte[] firma, String mensaje) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publica);
        publicSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        return publicSignature.verify(firma);
    }

    public byte[] encriptadoAsimetrico(PublicKey publica, String mensaje) throws Exception {
        Cipher encryptCipher = Cipher.getInstance(ALGORITMO_ASIMETRICO);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publica);
        return encryptCipher.doFinal(mensaje.getBytes());
    }

    public String desencriptadoAsimetrico(byte[] cifrado, PrivateKey privada) throws Exception {
        Cipher decriptCipher = Cipher.getInstance(ALGORITMO_ASIMETRICO);
        decriptCipher.init(Cipher.DECRYPT_MODE, privada);
        String decipheredMessage = new String(decriptCipher.doFinal(cifrado), StandardCharsets.UTF_8);
        System.out.println(decipheredMessage);
        return decipheredMessage;
    }

    public byte[] hmac(byte[] msg, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HMACSHA256");
        mac.init(key);
        return mac.doFinal(msg);
    }

    public boolean verificarIntegridad(byte[] msg, SecretKey key, byte[] hash) throws Exception {
        byte[] nuevo = hmac(msg, key);
        if (nuevo.length != hash.length) {
            return false;
        }
        for (int i = 0; i < nuevo.length; i++) {
            if (nuevo[i] != hash[i]) return false;
        }
        return true;
    }

    public SecretKey obtenerLlaveCifradoSimetrico(String semilla) throws Exception {
        byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] encodedhash = digest.digest(byte_semilla);
        byte[] encoded1 = new byte[32];
        System.arraycopy(encodedhash, 0, encoded1, 0, 32);
        SecretKey sk;
        sk = new SecretKeySpec(encoded1, "AES");
        return sk;
    }

    public SecretKey obtenerLlaveHMAC(String semilla) throws Exception {
        byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] encodedhash = digest.digest(byte_semilla);
        byte[] encoded2 = new byte[32];
        System.arraycopy(encodedhash, 32, encoded2, 0, 32);
        SecretKey sk;
        sk = new SecretKeySpec(encoded2, "AES");
        return sk;
    }

    public byte[] encriptadoSimetrico(byte[] msg, SecretKey key, IvParameterSpec iv, String id) throws Exception {
        Cipher decifrador = Cipher.getInstance(ALGORITMO_SIMETRICO);
        long start = System.nanoTime();
        decifrador.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] tmp = decifrador.doFinal(msg);
        long end = System.nanoTime();
        System.out.println(id + " --- Elapsed Time for SYM encryption in nano seconds: " + (end - start));
        return tmp;
    }

    public byte[] desencriptadoSimetrico(byte[] msg, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher decifrador = Cipher.getInstance(ALGORITMO_SIMETRICO);
        decifrador.init(Cipher.DECRYPT_MODE, key, iv);
        return decifrador.doFinal(msg);
    }

    public PublicKey obtenerLlavePublicaServidor(String nombreArchivo, String id) {
        FileInputStream is1;
        PublicKey pubkey = null;
        System.out.println(id + nombreArchivo);
        try {
            is1 = new FileInputStream(nombreArchivo);
            File f = new File(nombreArchivo);
            byte[] inBytes1 = new byte[(int) f.length()];
            is1.read(inBytes1);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(inBytes1);
            pubkey = kf.generatePublic(publicKeySpec);
            is1.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pubkey;
    }

    public PrivateKey obtenerLlavePrivadaServidor(String nombreArchivo, String id) {
        PrivateKey privkey = null;
        System.out.println(id + nombreArchivo);
        FileInputStream is2;
        try {
            is2 = new FileInputStream(nombreArchivo);
            File f2 = new File(nombreArchivo);
            byte[] inBytes2 = new byte[(int) f2.length()];
            is2.read(inBytes2);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(inBytes2);
            privkey = kf.generatePrivate(privateKeySpec);
            is2.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privkey;
    }
}