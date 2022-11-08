package seguridad20222_servidor;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SecurityFunctions {
    private static final String algoritmo_simetrico = "AES/CBC/PKCS5Padding";
    private static final String algoritmo_asimetrico = "RSA";

    public static byte[] sign(PrivateKey privada, String mensaje) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privada);
        privateSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        return privateSignature.sign();
    }

    public static boolean checkSignature(PublicKey publica, byte[] firma, String mensaje) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publica);
        publicSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        return publicSignature.verify(firma);
    }

    public static byte[] aenc(PublicKey publica, String mensaje) throws Exception {
        Cipher encryptCipher = Cipher.getInstance(algoritmo_asimetrico);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publica);
        return encryptCipher.doFinal(mensaje.getBytes());
    }

    public static String adec(byte[] cifrado, PrivateKey privada) throws Exception {
        Cipher decriptCipher = Cipher.getInstance(algoritmo_asimetrico);
        decriptCipher.init(Cipher.DECRYPT_MODE, privada);
        String decipheredMessage = new String(decriptCipher.doFinal(cifrado), StandardCharsets.UTF_8);
        System.out.println(decipheredMessage);
        return decipheredMessage;
    }

    public static byte[] hmac(byte[] msg, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HMACSHA256");
        mac.init(key);
        return mac.doFinal(msg);
    }

    public static boolean checkInt(byte[] msg, SecretKey key, byte[] hash) throws Exception {
        byte[] nuevo = hmac(msg, key);
        if (nuevo.length != hash.length) {
            return false;
        }
        for (int i = 0; i < nuevo.length; i++) {
            if (nuevo[i] != hash[i]) return false;
        }
        return true;
    }

    public static SecretKey csk1(String semilla) throws Exception {
        byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] encodedhash = digest.digest(byte_semilla);
        byte[] encoded1 = new byte[32];
        System.arraycopy(encodedhash, 0, encoded1, 0, 32);
        return new SecretKeySpec(encoded1, "AES");
    }

    public static SecretKey csk2(String semilla) throws Exception {
        byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] encodedhash = digest.digest(byte_semilla);
        byte[] encoded2 = new byte[32];
        System.arraycopy(encodedhash, 32, encoded2, 0, 32);
        return new SecretKeySpec(encoded2, "AES");
    }

    public static byte[] senc(byte[] msg, SecretKey key, IvParameterSpec iv, String id) throws Exception {
        Cipher decifrador = Cipher.getInstance(algoritmo_simetrico);
        long start = System.nanoTime();
        decifrador.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] tmp = decifrador.doFinal(msg);
        long end = System.nanoTime();
        System.out.println(id + " --- Elapsed Time for SYM encryption in nano seconds: " + (end - start));
        return tmp;
    }

    public static byte[] sdec(byte[] msg, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher decifrador = Cipher.getInstance(algoritmo_simetrico);
        decifrador.init(Cipher.DECRYPT_MODE, key, iv);
        return decifrador.doFinal(msg);
    }

    public static PublicKey read_kplus(String nombreArchivo, String id) {
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

    public static PrivateKey read_kmin(String nombreArchivo, String id) {
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
