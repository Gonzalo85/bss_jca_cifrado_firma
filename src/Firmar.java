import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;

/**
 * Clase encargada de firmar ficheros y verificarlos
 * @author Borja Alberto Tirado Galan & Gonzalo Bueno Rodriguez
 *
 */
public class Firmar {

	static Signature firma;

	String algorithm;

	static byte[] sig;

	/**
	 * Constructor parametrizado
	 * @param algorithm algoritmo de firmado
	 */
	public Firmar(String algorithm) {
		this.algorithm = algorithm;
		Firmar.sig = null;
	}
	/**
	 * Constructor por defecto
	 */
	public Firmar() {
		this.algorithm = "";
		Firmar.sig = null;
	}
	/**
	 * Metodo encargado de realizar el proceso de firmado de un fichero
	 * 
	 * @param fichero Parametro tipo String, referencia al fichero
	 * @param k       referencia de un objeto Claves
	 * @param String algFirmado algoritmo de firmado elegido por el usuario
	 * @return Retorna verdadero si la firma se ha realizado correctamente
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws SignatureException
	 */
	public static boolean firmado(String fichero, String algFirmado, PrivateKey k) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		boolean firmado = false;
		String alg1 = Options.cipherAlgorithms[0];
		System.out.println("Proceso de firmado de <" + fichero + "> con Algoritmo: " + algFirmado + "\n");

		// obtener instancia del objeto con el alg de firmado
		firma = Signature.getInstance(algFirmado);
		// iniciamos la firma con la clave privada que viene por parametros
		firma.initSign(k);
		// abrimos flujo de ficheros de lectura y su buffer
		FileInputStream fis = new FileInputStream(fichero);
		BufferedInputStream bis = new BufferedInputStream(fis);

		byte[] buffer = { 0x00 };

		// leemos fichero y firmamos
		int i;
		while ((i = bis.read(buffer)) > 0) {
			firma.update(buffer);
		}
		sig = firma.sign();

		// cerramos flujo de lectura
		bis.close();
		fis.close();

		// abrimos flujo de escritura y su buffer
		FileOutputStream fos = new FileOutputStream(fichero + ".sign");
		BufferedOutputStream bos = new BufferedOutputStream(fos);

		// creacion de cabecera y guardado
		Header header = new Header(Options.OP_SIGNED, alg1, algFirmado, sig);
		header.save(bos);

		// abrimos flujo de lectura de nuevo y su buffer
		fis = new FileInputStream(fichero);
		bis = new BufferedInputStream(fis);
		
		// escribimos en fichero
		while ((i = bis.read(buffer)) > 0) {
			bos.write(buffer);
		}

		// cierre de flujos
		bis.close();
		fis.close();
		bos.close();
		fos.close();
		
		firmado = true;

		return firmado;

	}

	/**
	 * Metodo encargado de realizar el proceso de verificacion de firma de un
	 * fichero
	 * 
	 * @param fichero Parametro tipo String, referencia al fichero
	 * @param k       referencia de un objeto Claves
	 * @return Retorna verdadero si la verificacion de la firma se ha realizado
	 *         correctamente.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws SignatureException
	 */
	public boolean verificarFirma(String fichero, Claves k) throws NoSuchAlgorithmException, InvalidKeyException,
			InvalidKeySpecException, IOException, SignatureException {
		boolean verifies = false;
		FileInputStream fis = new FileInputStream(fichero);
		FileOutputStream fos = new FileOutputStream(fichero + ".verificado");
		BufferedInputStream bis = new BufferedInputStream(fis);

		Header h = new Header();
		if (h.load(fis)) {
			firma = Signature.getInstance(h.getAlgorithm2()); // Obtener instancia del objeto:
			firma.initVerify(k.getPku()); // Iniciar para verificar firma con Clave Pública:

			byte[] buffer = { 0x00 };
			int i;
			while ((i = bis.read(buffer)) > 0) { // Procesar información a firmar:
				firma.update(buffer);
				fos.write(buffer);
			}

			bis.close();
			fos.close();
			fis.close();

			verifies = firma.verify(sig);
		}
		return verifies;
	}
}
