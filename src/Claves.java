import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Claves {

	public static final int tam = 512; // tamaño inicial para el generador

	public static String algorithm;

	private KeyPairGenerator kpg; // generador de par de claves

	private KeyPair claves;

	private PublicKey pku; // clave publica

	private PrivateKey pkr; // clave privada

	public Claves(String algorithm) {
		this.algorithm = algorithm;
		kpg = null;
		claves = null;
		pku = null;
		pkr = null;

	}

	public Claves() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Método para generar el par de claves, pública y privada.
	 * 
	 * 
	 * @return nada
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public void generarParDeClaves() throws NoSuchAlgorithmException, IOException {
		kpg = KeyPairGenerator.getInstance(Claves.algorithm);// obtenemos instancia del generador de claves
		kpg.initialize(tam);// iniciamos el generador con el tamaño
		claves = kpg.generateKeyPair();// generamos el par de claves

		pku = claves.getPublic();// guardamos la pública
		pkr = claves.getPrivate();// guardamos la privada

		guardarClave(pku, "publicKey");// guardado de clave pública en fichero publicKey.key
		guardarClave(pkr, "privateKey");// guardado de clave privada en fichero privateKey.key
	}

	/**
	 * Método para guardar las claves en ficheros
	 * 
	 * 
	 * @return nada
	 * @throws IOException
	 */
	private void guardarClave(java.security.Key key, String fichero) throws IOException {
		byte[] keyBytes = ((java.security.Key) key).getEncoded();
		FileOutputStream fos = new FileOutputStream(fichero + ".key");
		fos.write(keyBytes);
		fos.close();
	}

	/**
	 * Método para mostrar las claves por pantalla al usuario
	 * 
	 * @return nada
	 */
	public void mostrarClaves() {
		System.out.println("Clave pública: " + pku);
		System.out.println("Clave privada: " + pkr);

	}

	/**
	 * Método para cargar la clave publica como bytes de PublicKey
	 * 
	 * @return PublicKey key
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PublicKey cargarClavePublica(String fichero)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		PublicKey key;
		FileInputStream fis = new FileInputStream(fichero);
		int numbytes = fis.available();// obtenemos bytes totales
		byte[] bytes = new byte[numbytes];
		fis.read(bytes);
		fis.close();

		KeyFactory kf = KeyFactory.getInstance(Claves.algorithm);
		KeySpec keySpec = new X509EncodedKeySpec(bytes); // clave publica protegida
		key = kf.generatePublic(keySpec);
		return key;
	}

	/**
	 * Método para cargar la clave privada como bytes de PrivateKey
	 * 
	 * @return PrivateKey key
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PrivateKey cargarClavePrivada(String fichero)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		PrivateKey key;
		FileInputStream fis = new FileInputStream(fichero);
		int numbytes = fis.available();// obtenemos bytes totales
		byte[] bytes = new byte[numbytes];
		fis.read(bytes);
		fis.close();

		KeyFactory kf = KeyFactory.getInstance(Claves.algorithm);
		KeySpec keySpec = new PKCS8EncodedKeySpec(bytes); // clave privada protegida
		key = kf.generatePrivate(keySpec);
		return key;
	}

	public PublicKey getPku() {
		return pku;
	}

	public PrivateKey getPkr() {
		return pkr;
	}

}
