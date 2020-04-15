import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Clase Cifrar, encargada de realizar las funciones de cifrado y descifrado
 * @author Borja Alberto Tirado Galan & Gonzalo Bueno Rodriguez
 *
 */
public class Cifrar {

	public static final int blockSizeCiph = 53;

	public static final int blockSizeDc = 64;

	public static final byte[] arrayBytesCiph = new byte[blockSizeCiph];

	public static final byte[] arrayBytesDc = new byte[blockSizeDc];

	private Cipher c;

	private Cipher dc;

	/* Salt: conjunto de bytes aleatorios */
	private byte[] salt;

	/**
	 * Generador de datos aleatorios para cabecera
	 * 
	 * @param size tamano de la estructura
	 * @return estructura de datos aleatorios tipo byte []
	 */

	public static byte[] generateRandomSalt(int size) {
		if (size < 6 || size > 1024) {
			size = 6;
		}
		byte[] salt = new byte[size];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		return salt;
	}

	/**
	 * Metodo de cifrado del fichero, recibe por parámetros el fichero, el algoritmo
	 * a usar, que en este caso es siempre el algoritmo de clave pública
	 * RSA/ECB/PKCS1Padding y la clave publica que se usara para el cifrado
	 * 
	 * @param String    fichero con el nombre del fichero a cifrar
	 * @param String    alCifrado con el algoritmo de cifrado seleccionado
	 * @param PublicKey k clave publica usada para cifrar
	 * 
	 * @return boolean cifrado, se pone a true al terminar el cifrado
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 */
	public boolean cifrado(String fichero, String algCifrado, PublicKey k) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		boolean cifrado = false;
		String alg2 = Options.authenticationAlgorithms[0];
		salt = generateRandomSalt(8);

		System.out.println("Proceso de cifrado de <" + fichero + "> con Algoritmo: " + algCifrado + "\n");

		try {
			FileInputStream fis = new FileInputStream(fichero); // abrimos flujo para leer del fichero
			FileOutputStream fos = new FileOutputStream(fichero + ".cif");// flujo de salida para el nuevo fichero
																			// cifrado

			c = Cipher.getInstance(algCifrado);// instancia de Cipher con el algoritmo seleccionado
			c.init(Cipher.ENCRYPT_MODE, k); // iniciamos el cifrado
			
			// Escribimos los parametros en la cabecera
			Header header = new Header(Options.OP_PUBLIC_CIPHER, algCifrado, alg2, salt);
			header.save(fos);

			byte[] byteCifrado;
			int i;
			// Bucle de escritura
			while ((i = fis.read(arrayBytesCiph)) >= 0) {
				byteCifrado = c.doFinal(arrayBytesCiph, 0, i);
				fos.write(byteCifrado);
			}
			
			// Cierre de flujos
			fos.close();
			fis.close();
			cifrado = true;

		} catch (FileNotFoundException FileNotFoundException) {
			System.out.println("Fichero no encontrado: " + fichero + "\n");
		} catch (IOException IOException) {
			System.out.println("Error de E/S \n");
		} catch (Exception localException) {
			System.out.println(localException.getMessage() + "\n");
		}

		return cifrado;
	}

	/**
	 * Metodo para descifrar fichero con clave privada que previamente ha sido
	 * cifrado con clave publica, recibe por parámetros el fichero y la clave
	 * privada que se usara para el descifrado
	 * 
	 * @param String     fichero nombre del fichero a descifrar
	 * @param PrivateKey k clave privada a usar para descifrar
	 * @return boolean descifrado, se pone a true al terminar el descifrado
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 */
	public boolean descifrado(String fichero, PrivateKey k)
			throws FileNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		boolean descifrado = false;
		String alg = "";
		System.out.println("Proceso de descifrado de <" + fichero + ">\n");
		try {
			FileInputStream fis = new FileInputStream(fichero); // abrimos flujo para leer del fichero

			FileOutputStream fos = new FileOutputStream(fichero + ".cla");// flujo salida para el nuevo fichero
																			// descifrado

			Header header = new Header();
			header.load(fis);// leemos la cabecera para obtener el algoritmo usado, ya que se necesita para
								// descifrar

			System.out.println("El fichero se encuentra cifrado con el algoritmo de clave pública"
					+ header.getAlgorithm1() + ", obtenido de la cabecera");// mostramos algoritmo obtenido de cabecera
																			// para comprobar

			alg = header.getAlgorithm1();// obtenemos el algoritmo

			dc = Cipher.getInstance(alg);// iniciamos desencriptado con el algoritmo leido de la cabecera
			dc.init(Cipher.DECRYPT_MODE, k);

			byte[] byteDescifrado;

			// bucle de descifrado
			int i;
			while ((i = fis.read(arrayBytesDc)) >= 0) {
				byteDescifrado = dc.doFinal(arrayBytesDc, 0, i);
				fos.write(byteDescifrado);
			}
			// cierre de flujos
			fos.close();
			fis.close();
			descifrado = true;

		} catch (IOException localIOException) {
			System.out.println("\n[x] Proceso de descifrado incompleto: ");
			System.out.println("\n[x] 	Error de E/S.");
			System.out.println("\n[x] 	Comprueba que la ruta y credenciales son correctos\n");
		} catch (Exception localException) {
			System.out.println(localException.getMessage() + "\n");
			localException.printStackTrace();
		}
		return descifrado;
	}
}
