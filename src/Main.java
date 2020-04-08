import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {
	private Scanner opcion;
	private Cifrar cifrar;
	private Claves claves;
	private Firmar firmar;

	public Main() {
		this.opcion = new Scanner(System.in);
		this.cifrar = new Cifrar();
		this.claves = new Claves();
		this.firmar = new Firmar();
	}

	/**
	 * Metodo que muestra las opciones disponibles del programa
	 * 
	 * @return int op, opción elegida para el menú.
	 */
	public int menuOpciones() throws IOException {
		int op;
		System.out.println("===========================================================================");
		System.out.println("Elija la operacion que desea realizar con el fichero:");
		System.out.println("Nota: Los ficheros deben encontrarse en el mismo directorio que el principal");
		System.out.println("1. Generar claves");
		System.out.println("2. Mostrar claves");
		System.out.println("3. Firmar fichero");
		System.out.println("4. Validar firma fichero");
		System.out.println("5. Cifrar fichero con clave pública");
		System.out.println("6. Descifrar fichero con clave privada(complementaria a opción anterior)");
		System.out.println("0. Salir");
		System.out.println("===========================================================================");
		op = opcion.nextInt();

		return op;

	}

	/**
	 * Metodo para el menú de opciones 0: salir bucle pidiendo opciones hasta que el
	 * usuario elija 0
	 * 
	 * @return nada
	 */
	public void procesoPrincipal() throws IOException {
		boolean esc = false;
		int seleccion;
		while (!esc) {
			try {
				seleccion = menuOpciones();
				switch (seleccion) {
				case 0: // salir
					esc = true;
					break;
				case 1: // generar claves
					generarParDeClaves();
					break;
				case 2: // mostrar claves
					claves.mostrarClaves();
					break;
				case 3: // firmar fichero
					firmarFichero();
				case 4: // validar firma fichero
					validarFirma();
				case 5:// cifrarFichero
					cifrarFichero();
				case 6:// descifrar fichero
					descifrarFichero();
				default:
					System.out.println("Opcion incorrecta, vuelva a introducir otro valor (0-2)\n");
					break;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
		System.out.println("...Fin del programa...");
	}

	/**
	 * que llama al generar claves de la clase Claves, están con nombre fijos, pero
	 * se podrían pedir nombres de ficheros por pantalla al usuario y llamarlo con
	 * esos nombres
	 * 
	 * @return nada
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public void generarParDeClaves() throws NoSuchAlgorithmException, IOException {
		System.out.println(
				"Se va a generar el par de claves con RSA, la clave privada sera el archivo privateKey.key y la privada privateKey.key");
		System.out.println("Estarán guardadas en el directorio principal del programa.");
		claves.generarParDeClaves();
	}

	private void firmarFichero() {
		// TODO Auto-generated method stub

	}

	private void validarFirma() {

	}

	private void cifrarFichero() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String fichero = "";
		String algCifrado = "";
		boolean enc = false;
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		try {
			System.out.println("Introduzca el nombre del fichero que desea cifrar con la extension");
			System.out.print("Fichero: ");
			while (!enc) {
				fichero = br.readLine();
				if (Files.exists(Paths.get(fichero))) {
					enc = true;
				} else {
					System.err.println("ERROR! fichero no encontrado");
					System.out.println("Introduzca el nombre de nuevo, asegúrese que está en el mismo directorio");
				}
			}

			algCifrado = menuAlgoritmoCifrado();
			if (cifrar.cifrado(fichero, algCifrado , claves.getPku())) {
				System.out.println("-- Cifrado completado satisfactoriamente.\n"
						+ "Puede encontrarlo como " + fichero + ".cif");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	/**
	 * Método para mostrar las opciones de algoritmos de cifrado
	 * 
	 * @return 0
	 */
	private String menuAlgoritmoCifrado() {
		String algCifrado="";
		System.out.println("======================================================");
		System.out.println("Seleccione un algoritmo de cifrado de clave pública:");
		System.out.println("1. RSA");
		System.out.println("2. ECB");
		System.out.println("3. PCS1Padding");
		System.out.println("======================================================");
		
		int entrada = opcion.nextInt();
		switch (entrada) {
		case 1:
			algCifrado = Options.publicAlgorithms[entrada - 1];
			break;
		case 2:
			algCifrado = Options.publicAlgorithms[entrada - 1];
			break;
		case 3:
			algCifrado = Options.publicAlgorithms[entrada - 1];
			break;
		default:
			System.out.println("ERROR en la seleccion del algoritmo de cifrado...");
			System.out.println("Opcion seleccionada: " + entrada + "\n");
			break;
		}
		System.out.println("Algoritmo seleccionado: " + Options.publicAlgorithms[entrada - 1]);
		
		return algCifrado;
	}
	
	/**
	 * Metodo que llama al descifrado pidiendo al usuario por pantalla el nombre del
	 * fichero a descifrar Una vez descifrado mostrará al usuario por pantalla una
	 * confirmación
	 * 
	 * @return 0
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void descifrarFichero() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		String fichero = "";
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Introduzca el nombre del fichero que desea descifrar con la extension");
		System.out.println("Fichero: ");
		try {
			fichero = br.readLine();
		
			if (cifrar.descifrado(fichero, claves.getPkr())) {
				System.out.println("-- Fichero descifrado satisfactoriamente."+"\n"
						+ "Puede encontrarlo como " + fichero
						+ ".cla, si desea revisarlo en el explorador del S.O."
						+ " puede cambiar la extension a .txt ");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(final String[] args) throws IOException {
		Main main = new Main();
		main.procesoPrincipal();

	}

}