import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

import javax.crypto.Cipher;

public class Firmar {

    static Signature firma;
	
	String algorithm;
	
	public Firmar (String algorithm) {
		this.algorithm = algorithm;
	}

	public Firmar() {
		// TODO Auto-generated constructor stub
	}

	public static boolean firmado(String fichero, String algFirmado, PrivateKey k) {
		boolean firmado = false;
		String alg1 = Options.cipherAlgorithms[0];
		byte[] salt =  Cifrar.generateRandomSalt(8);
        System.out.println("Proceso de firmado de <" + fichero + "> con Algoritmo: " + algFirmado + "\n");
		
		try {
			//obtener instancia del objeto con el alg de firmado
			firma = Signature.getInstance(algFirmado);
			//iniciamos la firma con la clave privada que viene por parametros
			firma.initSign(k);
			//abrimos flujo de ficheros de lectura y su buffer
			FileInputStream fis = new FileInputStream(fichero);
			BufferedInputStream bis = new BufferedInputStream(fis);
			
			byte [] buffer = new byte [8];
			
			//leemos fichero y firmamos
			int i = bis.read(buffer);
			while(i>0) {
				firma.update(buffer);
				i = bis.read(buffer);
			}
			//cerramos flujo de lectura
			bis.close();
			fis.close();
			
			//abrimos flujo de escritura y su buffer
			FileOutputStream fos = new FileOutputStream(fichero+".sign");
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			
			//creacion de cabecera y guardado
			Header header = new Header(Options.OP_SIGNED,alg1,algFirmado,salt);
			header.save(bos);
			
			//abrimos flujo de lectura de nuevo y su buffer
			fis = new FileInputStream(fichero);
			bis = new BufferedInputStream(fis);
			
			//escribimos en fichero
			i = bis.read(buffer);
			while(i>0) {
				bos.write(buffer);
				i = bis.read(buffer);
			}
			//cierre de flujos
			bis.close();
			fis.close();
			bos.close();
			fos.close();
			firmado = true;
		
		}catch (FileNotFoundException FileNotFoundException) {
			System.out.println("Fichero no encontrado: " + fichero + "\n");
		} catch (IOException IOException) {
			System.out.println("Error de E/S \n");
		} catch (Exception localException) {
			System.out.println(localException.getMessage() + "\n");
		}
		return firmado;
	}
}
