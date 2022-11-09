package Cliente;

import Concurrente.Concurrente;
import Util.FuncionesDeSeguridad;
import Util.RespuestaInvalidaException;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;

public class ClienteThread extends Concurrente {

    private final PublicKey LLAVE_PUB_SERVIDOR;

    public ClienteThread(Socket socket, int id, String nombre) {
        super(socket, id, nombre);
        LLAVE_PUB_SERVIDOR = FNS_SEGURIDAD.obtenerLlavePublicaServidor("datos_asim_srv.pub", MENSAJE_DEFECTO);
    }

    public void run() {
        // Se definen los canales de comunicacion
        try {
            imprimirInfo("iniciando");
            generarCanalesComunicacion();
        } catch (IOException e) {
            e.printStackTrace();
            imprimirError("se detecto un error al iniciar los canales de comunicacion");
        }

        // Empieza el intercambio de información
        try {
            // Paso 1, el cliente inicia la comunicacion con el servidor
            canalEscritura.println(INICIO_SEGURO);
            imprimirInfo(String.format("mensaje de inicilizacion %s enviado al servidor", INICIO_SEGURO));

            // Deberia corresponder al mensaje enviado en la primera parte del paso 3 del servidor
            // el mensaje con g, p & y
            String gpy = canalLectura.readLine();
            imprimirInfo("mensaje del servidor con gpy recibido -> " + gpy);

            // Deberia corresponder al mensaje enviado en la segunda parte del paso 3 del servidor
            // el mensaje con g, p & y firmado con la llave privada del servidor
            // cabe resaltar que viene comprimido en formato hexadecimal
            String firma = canalLectura.readLine();
            imprimirInfo("mensaje con gpy cifrado del servidor recibido -> " + firma);

            // Paso 4 y 5
            // mas detalles el cuerpo del metodo
            validarFirma(firma, gpy);

            // Paso 6
            // mas detalles en el cuerpo del metodo
            Tripla<BigInteger, BigInteger, BigInteger> preLlave = generarPreLlave(gpy);

            // Paso 7
            // mas detalle en el cuerpo del metodo
            obtenerLlavesSimetricas(preLlave.a, preLlave.b, preLlave.c);

            // Paso 8
            // mas detalle en el cuerpo del metodo
            enviarConsultaConIntegridad();

            // Ayuda a terminar el paso 10 (que es ejecutado por el servidor)
            // mas detalles en el cuerpo
            validarRespuestaIntegridadConsultaServidor();

            // Pasos  12 y 13
            // mas detalles en el cuerpo del metodo
            manejarRespuestaConsulta();

        } catch (RespuestaInvalidaException e) {
            imprimirError(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            imprimirError("se detecto un error durante la ejecucion");
        }

        // Se cierra el thread/delegado/cliente
        try {
            cerrarCanalesComunicacion();
            imprimirInfo("canales de comunicacion cerrados exitosamente");
            SOCKET.close();
            imprimirInfo("socket y cliente concurrente cerrados exitosamente");
        } catch (IOException e) {
            e.printStackTrace();
            imprimirError("cliente concurrente finalizado con errores");
        }

    }

    public void validarFirma(String firma, String gpy) throws Exception {
        // Paso 4, consiste en verificar la autenticacion del gpy anteriormente recibido
        // con la llave publica del servidor y el gpy cifrado
        long start = System.nanoTime();
        boolean laFirmaEsVeridica = FNS_SEGURIDAD.verificarFirma(LLAVE_PUB_SERVIDOR, hexaStr2byte(firma), gpy);
        long end = System.nanoTime();
        FuncionesDeSeguridad.write(end - start, "verificar_firma", ID);

        // Paso 5, consiste en responder un mensaje al servidor
        // informando si la firma fue validada o no
        if (laFirmaEsVeridica) {
            canalEscritura.println(MENSAJE_OK);
            imprimirInfo(String.format("respuesta de verificacion de firma enviada el servidor -> %s", MENSAJE_OK));
            imprimirInfo("la firma es veridica, el servidor es quien dice ser :)");
        } else {
            canalEscritura.println(MENSAJE_ERROR);
            imprimirInfo(String.format("respuesta de verificacion de firma enviada el servidor -> %s", MENSAJE_ERROR));
            throw new RespuestaInvalidaException(
                    "la firma no es valida, la conexion no es segura -> cerrando conexion...");
        }
    }

    public Tripla<BigInteger, BigInteger, BigInteger> generarPreLlave(String gpy) {
        // Paso 6a, consiste en calcular o generar el 'y' (o G^y) del cliente
        // El cliente sabe como desconcatenar lo que le manda el servidor
        String[] gpyArr = gpy.split(";");
        BigInteger g = new BigInteger(gpyArr[0]);
        BigInteger p = new BigInteger(gpyArr[1]);
        BigInteger yServidor = new BigInteger(gpyArr[2]);
        long start = System.nanoTime();
        BigInteger x = generarX();
        BigInteger y = calcularY(g, x, p); // Listo :D!
        long end = System.nanoTime();
        FuncionesDeSeguridad.write(end - start, "gy-cliente", ID);
        imprimirInfo("G^y o y del cliente generada exitosamente -> " + y);

        // Paso 6b, consiste en enviar el y generado en el paso anterior al servidor
        // este y le va a servir al servidor para calcular su propia llave maestra
        canalEscritura.println(y.toString());
        imprimirInfo("y generado enviado al servidor -> " + y);
        return new Tripla<>(yServidor, x, p);
    }

    public void obtenerLlavesSimetricas(BigInteger yServidor, BigInteger x, BigInteger p) throws Exception {
        // Primera parte del paso 7a, consiste en que el cliente genera la llave maestra
        // en este punto el cliente tiene la misma llave maestra que el servidor
        // esto gracias a Deffie-Hellman
        String llaveMaestra = calcularLlaveMaestra(yServidor, x, p).toString();

        imprimirInfo("llave maestra generada -> " + llaveMaestra);

        // Segunda parte del paso 7b, consiste en que el cliente genere la llave simetrica para cifrar
        // se hace con los primeros 256 bits de la llave maestra
        llaveCifrado = FNS_SEGURIDAD.obtenerLlaveCifradoSimetrico(llaveMaestra);
        imprimirInfo("llave de cifrado simetrico generada -> " + byte2HexaStr(llaveCifrado.getEncoded()));

        // Tercera parte del paso 7b, consiste en que el cliente genere la llave simetrica para integridad
        // se hace con los ultimos 256 bits de la llave maestra
        long start = System.nanoTime();
        llaveHMAC = FNS_SEGURIDAD.obtenerLlaveHMAC(llaveMaestra);
        long end = System.nanoTime();
        FuncionesDeSeguridad.write(end - start, "hmac", ID);
        imprimirInfo("llave de integridad HMAC generada -> " + byte2HexaStr(llaveHMAC.getEncoded()));
    }

    public void enviarConsultaConIntegridad() throws Exception {
        // Vector de inicilizacion que es un componente del algoritmo de cifrado simetrico escogido
        // tambien se envia al servidor para que este pueda descifrar
        String vectorInicializacion = generarIv();
        imprimirInfo("vector de inicializacion aleatorio generado -> " + vectorInicializacion);
        // Paso 8, consiste en enviar una consulta al servidor cifrada simetricamente
        // un hash de dicha consulta, con fines de integridad
        // el vector de inicializacion con la que fue cifrada la consulta
        long start = System.nanoTime();
        byte[] consulta = String.valueOf(Math.abs((new SecureRandom()).nextInt())).getBytes(StandardCharsets.UTF_8);
        imprimirInfo("nueva consulta (valor real) -> " + (new String(consulta, StandardCharsets.UTF_8)));
        String consultaCifrada = byte2HexaStr(
                FNS_SEGURIDAD.encriptadoSimetrico(consulta, llaveCifrado, hexaStr2Iv(vectorInicializacion),
                        String.valueOf(ID)));
        long end = System.nanoTime();
        FuncionesDeSeguridad.write(end - start, "cifrar", ID);
        imprimirInfo("consulta cifrada -> " + consultaCifrada);
        String codigoIntegridad = byte2HexaStr(FNS_SEGURIDAD.hmac(consulta, llaveHMAC));
        imprimirInfo("codigo HMAC de integridad de la consulta -> " + codigoIntegridad);
        String consultaCompleta = String.format("%s;%s;%s", consultaCifrada, codigoIntegridad, vectorInicializacion);
        canalEscritura.println(consultaCompleta);
        imprimirInfo("consulta completa cifrada enviada al servidor -> " + consultaCompleta);
    }

    public void validarRespuestaIntegridadConsultaServidor() throws Exception {
        // Esto debe corresponder a lo enviado en el paso 10 por el servidor
        // es un OK si se valido integridad en la consulta enviada
        // es un ERROR si no hubo integridad, esto nos saca de la conexion
        String respuestaIntegridad = canalLectura.readLine();
        imprimirInfo("respuesta del servidor sobre la integridad de la consulta enviada -> " + respuestaIntegridad);
        if (respuestaIntegridad.equals(MENSAJE_ERROR)) {
            throw new RespuestaInvalidaException(
                    "el servidor no pudo validar la integridad de la consulta enviada, cerrando conexion...");
        }
    }

    private Pair<Boolean, String> verificarIntegridadRespuestaServidor() throws Exception {
        // Paso 12, consiste en recibir la respuesta a la consulta por parte del servidor
        // y verificar su integridad
        String respuestaCompleta = canalLectura.readLine();
        imprimirInfo("respuesta a la consulta por parte del servidor recibida -> " + respuestaCompleta);
        String[] respuestaArr = respuestaCompleta.split(";");
        byte[] respuestaCifrada = hexaStr2byte(respuestaArr[0]);
        byte[] codigoIntegridad = hexaStr2byte(respuestaArr[1]);
        IvParameterSpec vectorInicializacionV = hexaStr2Iv(respuestaArr[2]);
        byte[] respuestaDescifrada = FNS_SEGURIDAD.desencriptadoSimetrico(respuestaCifrada, llaveCifrado,
                vectorInicializacionV);
        String respuestaDescifradaStr = (new String(respuestaDescifrada, StandardCharsets.UTF_8));
        imprimirInfo("respuesta descifrada -> " + respuestaDescifradaStr);
        return new Pair<>(FNS_SEGURIDAD.verificarIntegridad(respuestaDescifrada, llaveHMAC, codigoIntegridad),
                respuestaDescifradaStr);
    }

    private void manejarRespuestaConsulta() throws Exception {
        // Paso 12, mas detalles en el cuerpo del metodo
        Pair<Boolean, String> verificacion = verificarIntegridadRespuestaServidor();

        // Paso 13
        // informa al servidor si hubo integridad y lanza error en caso de que no
        if (!verificacion.p) {
            canalEscritura.println(MENSAJE_ERROR);
            imprimirInfo(
                    "respuesta de verificaicon de integridad a la respuesta de la consulta enviada al servidor -> " + MENSAJE_ERROR);
            throw new RespuestaInvalidaException(
                    "no hay integridad en la respuesta de la consulta, conexion insegura, cerrando conexion...");
        }
        canalEscritura.println(MENSAJE_OK);
        imprimirInfo(
                "respuesta de verificaicon de integridad a la respuesta de la consulta enviada al servidor -> " + MENSAJE_OK);
        imprimirInfo("nadie ha modificado la respuesta a la consulta, tiene integridad :)");
        imprimirInfo("la respuesta a la consulta es -> " + verificacion.g);
    }
}