import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Cifrar {
	
	public static final int blockSize = 53;
	
	public static final byte[] arrayBytes = new byte[blockSize];
	
	private Cipher c;
	
	/* Salt: conjunto de bytes aleatorios */
	private byte[] salt;
	
	/**
	 * Generador de datos aleatorios
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

	public boolean cifrado(String fichero, String algCifrado, PublicKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		boolean cifrado = false;
		String alg2 = "";
		salt = generateRandomSalt(8);
		
		System.out.println("Proceso de cifrado de <" + fichero + "> con Algoritmo: " + algCifrado + "\n");
		
		try {
		c = Cipher.getInstance(algCifrado);//instancia de Cipher con el algoritmo seleccionado
		
		FileInputStream fis = new FileInputStream(fichero); //abrimos flujo para leer del fichero 
		
		FileOutputStream fos = new FileOutputStream(fichero+".cif");//flujo de salida para el nuevo fichero cifrado
		
		c.init(Cipher.ENCRYPT_MODE, k); //iniciamos el cifrado 
		
		Header header = new Header(Options.OP_PUBLIC_CIPHER, algCifrado, alg2, salt);
		
		header.save(fos);//guardamos en cabecera
		
		byte [] byteCifrado;
		int i = fis.read(arrayBytes);
		//bucle de escritura
		while(i > 0) {
			byteCifrado = c.doFinal(arrayBytes, 0 ,i);
			fos.write(byteCifrado);
			i = fis.read(arrayBytes);
		}
		//cierre de flujos
		fos.close();
		fis.close();
		cifrado = true;
		
		}catch (FileNotFoundException FileNotFoundException) {
			System.out.println("Fichero no encontrado: " + fichero + "\n");
		} catch (IOException IOException) {
			System.out.println("Error de E/S \n");
		} catch (Exception localException) {
			System.out.println(localException.getMessage() + "\n");
		}
	
		return cifrado;
	}

	public boolean descifrado(String fichero, PrivateKey k) throws FileNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		boolean descifrado = false;
		String alg = "";
		System.out.println("Proceso de descifrado de <" + fichero + ">\n");
		try {
		FileInputStream fis = new FileInputStream(fichero); // abrimos flujo para leer del fichero

		FileOutputStream fos = new FileOutputStream(fichero + ".cla");// flujo salida para el nuevo fichero descifrado
		
		Header header = new Header();
		header.load(fis);//leemos la cabecera para obtener el algoritmo usado, ya que se necesita para descifrar
		
		System.out.println("El fichero se encuentra cifrado con el algoritmo "
				+header.getAlgorithm1()+", obtenido de la cabecera");//mostramos algoritmo obtenido de cabecera para comprobar
		
		alg = header.getAlgorithm1();//obtenemos el algoritmo
		
		c = Cipher.getInstance(alg);//iniciamos desencriptado con el algoritmo leido de la cabecera
		c.init(Cipher.DECRYPT_MODE, k);

		byte[] byteDescifrado;
		
		//bucle de descifrado
		int i = fis.read(arrayBytes);
		while(i>0) {
			byteDescifrado = c.doFinal(arrayBytes,0,i);
			fos.write(byteDescifrado);
			i = fis.read(arrayBytes);
		}
		//cierre de flujos
		fos.close();
		fis.close();
		
		}catch (IOException localIOException) {
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
