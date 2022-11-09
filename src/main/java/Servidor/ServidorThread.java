package Servidor;

import Concurrente.Concurrente;
import Util.RespuestaInvalidaException;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;

public class ServidorThread extends Concurrente {
	private final int MODO;
	private final PrivateKey LLAVE_PRIV_SERVIDOR;

	public ServidorThread(int modo, Socket socket, int id, String nombre) {
		super(socket, id, nombre);
		/*
		 * Los servidores concurrentes se ejecutan en uno de los tres modos:
		 * 0-ERROR
		 * 1-OK_ERROR
		 * 2-OK_OK
		 */
		MODO = modo;
		LLAVE_PRIV_SERVIDOR = FNS_SEGURIDAD.
				obtenerLlavePrivadaServidor("datos_asim_srv.pri", MENSAJE_DEFECTO);
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
			// Paso 1
			// mas detalles en el cuerpo del metodo
			verificarInicilizacion();

			// Paso 2 (genera parametros para DH (g, p, y (o G^x)) )
			Pair < BigInteger, BigInteger > gp = generarGyP();
			BigInteger x = generarX();
			BigInteger y = calcularY(gp.g, x, gp.p);
			String datosPreLlave = String.format("%s;%s;%s", gp.g.toString(), gp.p.toString(), y.toString());
			imprimirInfo("datos de pre-llave generados exitosamente");

			// Primera parte del paso 3, enviando g, p & y al cliente
			canalEscritura.println(datosPreLlave);
			imprimirInfo("datos de pre-llave enviados al cliente -> " + datosPreLlave);

			switch (MODO) {
				case 0 -> prueba0(datosPreLlave);
				case 1 -> prueba1(datosPreLlave, x, gp.p);
				case 2 -> prueba2(datosPreLlave, x, gp.p);
				default -> imprimirError("modo invalido -> " + MODO);
			}

		} catch (RespuestaInvalidaException e) {
			imprimirError(e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			imprimirError("se detecto un error durante la ejecucion");
		}

		// Se cierra el servidor concurrente/delegado/thread
		try {
			cerrarCanalesComunicacion();
			imprimirInfo("canales de comunicacion cerrados exitosamente");
			SOCKET.close();
			imprimirInfo("socket y servidor concurrente cerrados exitosamente");
		} catch (IOException e) {
			e.printStackTrace();
			imprimirError("servidor concurrente finalizado con errores");
		}

	}

	private void prueba0(String datosPreLlave) throws Exception {
		// Prueba 0: la verificacion de la firma debe fallar
		// generamos el error a proposito
		imprimirInfo("ejecutando la prueba 0");

		// Va desde el paso 3 (ejecutado por el servidor) hasta el 5 (ejecutado por el cliente)
		invalidarFirmaIncorrecta(datosPreLlave);
	}

	private void prueba1(String datosPreLlave, BigInteger x, BigInteger p) throws Exception {
		// Test 1: la verificacion de la firma debería estar bien pero
		// la verificacion de integridad deberia fallar
		// generamos el error a proposito
		imprimirInfo("ejecutando la prueba 1");

		// Va desde el paso 3 (ejecutado por el servidor) hasta el 5 (ejecutado por el cliente)
		// mas detalle en el cuerpo del metodo
		validarFirmaCorrecta(datosPreLlave);

		// El paso 7
		// mas detalle en el cuerpo del metodo
		obtenerLlavesSimetricas(x, p);

		// Del paso 9 al 10
		// mas detalle en el cuerpo del metodo
		String consulta = manejarConsulta();

		// Paso 11
		// mas detalle en el cuerpo del metodo
		enviarRespuestaSinIntegridad(consulta);

		// Termiancion del paso 13
		// mas info en el cuerpo del metodo
		verificarRespuestaSinIntegridad();
	}

	private void prueba2(String datosPreLlave, BigInteger x, BigInteger p) throws Exception {
		// Test 1: la verificacion de la firma debería estar bien pero
		// la verificacion de integridad deberia fallar
		// generamos el error a proposito
		imprimirInfo("ejecutando la prueba 1");

		// Va desde el paso 3 (ejecutado por el servidor) hasta el 5 (ejecutado por el cliente)
		// mas detalle en el cuerpo del metodo
		validarFirmaCorrecta(datosPreLlave);

		// El paso 7
		// mas detalle en el cuerpo del metodo
		obtenerLlavesSimetricas(x, p);

		// Del paso 9 al 10
		// mas detalle en el cuerpo del metodo
		String consulta = manejarConsulta();

		// Paso 11
		// mas detalle en el cuerpo del metodo
		enviarRespuestaConIntegridad(consulta);

		// Termiancion del paso 13
		// mas info en el cuerpo del metodo
		verificarRespuestaConIntegridad();
	}

	public void verificarInicilizacion() throws Exception {
		// Deberia corresponder al mensaje enviado en el paso 1 del cliente ("SECURE INIT")
		String inicializacionCliente = canalLectura.readLine();
		imprimirInfo("Mensaje de inicializacion de un cliente recibido -> " + inicializacionCliente);

		if (!inicializacionCliente.equals(INICIO_SEGURO)) {
			throw new RespuestaInvalidaException("mensaje de inicializacion invalido -> " +
					inicializacionCliente);
		}
	}

	public void obtenerLlavesSimetricas(BigInteger x, BigInteger p) throws Exception {
		// Primera parte del paso 7b, consiste en que el servidor genere la llave maestra
		// en este punto el servidor tiene la misma llave maestra que el cliente
		// esto gracias a Deffie-Hellman
		String llaveMaestra = obtenerLlaveMaestra(x, p);
		imprimirInfo("llave maestra generada -> " + llaveMaestra);

		// Segunda parte del paso 7b, consiste en que el servidor genere la llave simetrica para cifrar
		// se hace con los primeros 256 bits de la llave maestra
		llaveCifrado = FNS_SEGURIDAD.obtenerLlaveCifradoSimetrico(llaveMaestra);
		imprimirInfo("llave de cifrado simetrico generada -> " + byte2HexaStr(llaveCifrado.getEncoded()));

		// Tercera parte del paso 7b, consiste en que el servidor genere la llave simetrica para integridad
		// se hace con los ultimos 256 bits de la llave maestra
		llaveHMAC = FNS_SEGURIDAD.obtenerLlaveHMAC(llaveMaestra);
		imprimirInfo("llave de integridad HMAC generada -> " + byte2HexaStr(llaveHMAC.getEncoded()));
	}

	private void invalidarFirmaIncorrecta(String datosPreLlave) throws Exception {
		PrivateKey llavePrivadaErronea = generarLlavePrivadaAleatoriaRSA();
		// ERROR: -> se firma con una llave privada diferente a la del servidor
		String autenticacionErronea = byte2HexaStr(FNS_SEGURIDAD.firmarConCifradoAsimetrico(llavePrivadaErronea, datosPreLlave));

		// Segunda parte del paso 3, se envia gpy firmado, en este caso erroneamente
		canalEscritura.println(autenticacionErronea);
		imprimirInfo("autenticacion erronea enviada al cliente -> " + autenticacionErronea);

		// Terminacion del paso 5, el cliente envia la respuesta de la validacion de la firma erronea
		// consiste en que el servidor valide que el cliente haya rechazado, correctamente, una firma invalida
		String respuestaCliente = canalLectura.readLine();
		imprimirInfo("respuesta de autenticacion erronea recibida -> " + respuestaCliente);
		if (respuestaCliente.equals(MENSAJE_ERROR)) {
			imprimirInfo("==========> Prueba 0: exitosa (el servidor envia la firma equivocada)");
		} else if (respuestaCliente.equals(MENSAJE_OK)) {
			throw new RespuestaInvalidaException("==========> Prueba 0: fallida (el cliente valida una firma equivocada)");
		} else {
			throw new RespuestaInvalidaException("==========> Prueba 0: fallida (el cliente ha retornado un valor invalido) -> " +
					respuestaCliente);
		}
	}

	private void validarFirmaCorrecta(String datosPreLlave) throws Exception {
		// Segunda parte del paso 3, consiste en que el servidor le envia una firma correcta al cliente
		// esto para que este pueda validar la identidad del servidor
		// la firma es gpy cifrado con la llave privada del servidor
		String firma = byte2HexaStr(FNS_SEGURIDAD.firmarConCifradoAsimetrico(LLAVE_PRIV_SERVIDOR, datosPreLlave));
		canalEscritura.println(firma);
		imprimirInfo("autenticacion correcta enviada al cliente -> " + firma);

		// Esto deberia corresponder al mensaje enviado por el cliente en el paso 5
		// este mensaje es simplemente OK o ERROR segun la validez de la firma
		// consiste en que el servidor valida que el cliente haya validado correctamente su firma
		String respuestaCliente = canalLectura.readLine();
		imprimirInfo("respuesta de autenticacion correcta recibida -> " + respuestaCliente);
		if (respuestaCliente.equals("OK")) {
			imprimirInfo("==========> Prueba 1a: exitosa (el cliente valida una firma correcta)");
		} else if (respuestaCliente.equals("ERROR")) {
			throw new RespuestaInvalidaException("==========> Prueba 1a: fallida (el cliente invalida una firma correcta)");
		} else {
			throw new RespuestaInvalidaException("==========> Prueba 1a: fallida desastrosamente (el cliente ha retornado un valor invalido) -> " +
					respuestaCliente);
		}
	}

	private String obtenerLlaveMaestra(BigInteger x, BigInteger p) throws Exception {
		// Recibiendo el y por parte del cliente
		String y = canalLectura.readLine();
		imprimirInfo("se recibe el y por parte del cliente -> " + y);
		// Se calcula la llave maestra (y)^x mod n
		BigInteger yb = new BigInteger(y);
		return calcularLlaveMaestra(yb, x, p).toString();
	}

	private Pair < Boolean, String > recibirYVerificarIntegridadConsulta() throws Exception {
		// Paso 9, consiste en recibir una consulta por parte del cliente y verificar su integridad
		String consultaCompleta = canalLectura.readLine();
		imprimirInfo("consulta por parte del cliente recibida -> " + consultaCompleta);
		String[] consultaArr = consultaCompleta.split(";");
		byte[] consultaCifrada = hexaStr2byte(consultaArr[0]);
		byte[] codigoIntegridad = hexaStr2byte(consultaArr[1]);
		IvParameterSpec vectorInicializacionV = hexaStr2Iv(consultaArr[2]);
		byte[] consultaDescifrada = FNS_SEGURIDAD.desencriptadoSimetrico(consultaCifrada,
				llaveCifrado, vectorInicializacionV);
		String consultaDescifradaStr = (new String(consultaDescifrada, StandardCharsets.UTF_8));
		imprimirInfo("consulta descifrada -> " + consultaDescifradaStr);
		return new Pair < > (FNS_SEGURIDAD.verificarIntegridad(consultaDescifrada, llaveHMAC, codigoIntegridad),
				consultaDescifradaStr);
	}

	private String manejarConsulta() throws Exception {
		// Paso 9
		// mas detalle en el cuerpo del metodo
		Pair < Boolean, String > hayIntegridad = recibirYVerificarIntegridadConsulta();

		// Paso 10, se toma una decision en base a la verificacion
		// si no se pudo verificar la integridad de la consulta, se le comunica al cliente el ERROR y se cierra conexion
		// si se verifica la prueba sigue normalmente
		// cabe resaltar que este error no es esperado en la prueba
		if (!hayIntegridad.p) {
			canalEscritura.println(MENSAJE_ERROR);
			imprimirInfo("respuesta de verificacion de integridad de la consulta enviada al cliente -> " +
					MENSAJE_ERROR);
			throw new RespuestaInvalidaException("==========> error inesperado en la prueba1, no hay integridad en la consulta recibida por parte del cliente");
		}
		canalEscritura.println(MENSAJE_OK);
		imprimirInfo("respuesta de verificacion de integridad de la consulta enviada al cliente -> " +
				MENSAJE_OK);
		imprimirInfo("la consulta tiene integridad, nadie ha modificado el mensaje :)");
		return hayIntegridad.g;
	}

	private void verificarRespuestaSinIntegridad() throws Exception {
		// Termina el paso 13
		// consiste en verificar la respuesta del cliente en cuanto a la integridad
		// de la respuesta de la consulta recibida
		String verificacionCliente = canalLectura.readLine();
		if (verificacionCliente.equals(MENSAJE_ERROR)) {
			imprimirInfo("==========> Prueba 1b: exitosa (el cliente rechaza una respuesta sin integridad)");
		} else if (verificacionCliente.equals(MENSAJE_OK)) {
			throw new RespuestaInvalidaException("==========> Prueba 1b: fallida (el cliente acepta una respuesta sin integridad)");
		} else {
			throw new RespuestaInvalidaException("==========> Prueba 1b: fallida desastrosamente, respuesta invalida -> " + verificacionCliente);
		}
	}

	private void verificarRespuestaConIntegridad() throws Exception {
		// Termina el paso 13
		// consiste en verificar la respuesta del cliente en cuanto a la integridad
		// de la respuesta de la consulta recibida
		String verificacionCliente = canalLectura.readLine();
		if (verificacionCliente.equals(MENSAJE_OK)) {
			imprimirInfo("==========> Prueba 1b: exitosa (el cliente acepta una respuesta con integridad)");
		} else if (verificacionCliente.equals(MENSAJE_ERROR)) {
			throw new RespuestaInvalidaException("==========> Prueba 1b: fallida (el cliente rechaza una respuesta con integridad)");
		} else {
			throw new RespuestaInvalidaException("==========> Prueba 1b: fallida desastrosamente, respuesta invalida -> " + verificacionCliente);
		}
	}

	private void enviarRespuestaConIntegridad(String consulta) throws Exception {
		// Vector de inicilizacion que es un componente del algoritmo de cifrado simetrico escogido
		// tambien se envia al cliente para que este pueda descifrar
		String vectorInicializacion = generarIv();
		imprimirInfo("vector de inicializacion aleatorio generado -> " + vectorInicializacion);
		// Paso 11, consiste en enviar una respuesta a la consulta al cliente, cifrada simetricamente
		// un hash de dicha respuesta, con fines de integridad
		// el vector de inicializacion con la que fue cifrada la respuesta
		String respuesta = String.valueOf(Integer.parseInt(consulta) + 1);
		byte[] respuestaBytes = respuesta.getBytes(StandardCharsets.UTF_8);
		imprimirInfo("la respuesta a la consulta es -> " + respuesta);
		byte[] respuestaCifradaBytes = FNS_SEGURIDAD.encriptadoSimetrico(respuestaBytes, llaveCifrado,
				hexaStr2Iv(vectorInicializacion), String.valueOf(ID));
		String respuestaCifrada = byte2HexaStr(respuestaCifradaBytes);
		imprimirInfo("respuesta cifrada -> " + respuestaCifrada);
		String codigoIntegridad = byte2HexaStr(FNS_SEGURIDAD.hmac(respuestaBytes, llaveHMAC));
		imprimirInfo("codigo HMAC de integridad de la respuesta -> " + codigoIntegridad);
		String respuestaCompleta = String.format("%s;%s;%s", respuestaCifrada,
				codigoIntegridad, vectorInicializacion);
		canalEscritura.println(respuestaCompleta);
		imprimirInfo("respuesta completa cifrada enviada al cliente -> " + respuestaCompleta);
	}

	private void enviarRespuestaSinIntegridad(String consulta) throws Exception {
		// Vector de inicilizacion que es un componente del algoritmo de cifrado simetrico escogido
		// tambien se envia al cliente para que este pueda descifrar
		String vectorInicializacion = generarIv();
		imprimirInfo("vector de inicializacion aleatorio generado -> " + vectorInicializacion);
		// Paso 11, consiste en enviar una respuesta a la consulta al cliente, cifrada simetricamente
		// un hash de dicha respuesta, con fines de integridadimprimirInfo("la respuesta a la consulta es -> " + respuesta);
		// el vector de inicializacion con la que fue cifrada la respuesta
		String respuesta = String.valueOf(Integer.parseInt(consulta) + 1);
		byte[] respuestaBytes = respuesta.getBytes(StandardCharsets.UTF_8);
		String respuestaModificada = respuesta + "hackeado xdxd";
		byte[] respuestaModificadaBytes = respuestaModificada.getBytes(StandardCharsets.UTF_8);
		imprimirInfo("la respuesta a la consulta es -> " + respuesta);
		imprimirInfo("la respuesta modificada es -> " + respuestaModificada);
		// Asumamos que se logro hackear la llave de cifrado, pero no la de HMAC
		byte[] respuestaModificadaCifradaBytes = FNS_SEGURIDAD.encriptadoSimetrico(respuestaModificadaBytes, llaveCifrado,
				hexaStr2Iv(vectorInicializacion), String.valueOf(ID));
		String respuestaModificadaCifrada = byte2HexaStr(respuestaModificadaCifradaBytes);
		imprimirInfo("respuesta modificada cifrada -> " + respuestaModificadaCifrada);
		String codigoIntegridadCorrecto = byte2HexaStr(FNS_SEGURIDAD.hmac(respuestaBytes, llaveHMAC));
		imprimirInfo("codigo HMAC de integridad de la respuesta correcta -> " + codigoIntegridadCorrecto);
		String respuestaCompleta = String.format("%s;%s;%s", respuestaModificadaCifrada,
				codigoIntegridadCorrecto, vectorInicializacion);
		canalEscritura.println(respuestaCompleta);
		imprimirInfo("respuesta completa sin integridad cifrada enviada al cliente -> " + respuestaCompleta);
	}
	private Pair < BigInteger, BigInteger > generarGyP() {
		int bitLength = 1024;
		SecureRandom rnd = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(bitLength, rnd);
		BigInteger g = BigInteger.probablePrime(bitLength, rnd);
		return new Pair < > (p, g);
	}

	private PrivateKey generarLlavePrivadaAleatoriaRSA() throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(1024, new SecureRandom());
		KeyPair kp = kpGen.genKeyPair();
		return kp.getPrivate();
	}
}