
import java.io.*;
import java.net.*;
import java.security.KeyStore;

import javax.net.*;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;

/*********************************************************************
 * ClassFileServer.java -- a simple file server that can server
 * Http get request in both clear and secure channel
 *
 * The ClassFileServer implements a ClassServer that
 * reads files from the file system. See the
 * doc for the "Main" method for how to run this
 * server.
 ********************************************************************/

public class ClassFileServer extends ClassServer {

    private static String     		docroot;
    private static int 		DefaultServerPort = 9001;
	private static String 	raiz = "/home/juancho/seg/";
	

	//	ks.load(new FileInputStream("c:/comun/escuela/seguridad_bolonia/practica2013/cliente/testkeys.jks"), passphrase);

    /**********************************************************
     * Constructs a ClassFileServer.
     *
     * @param path the path where the server locates files
     **********************************************************/
    public ClassFileServer(ServerSocket ss, String docroot,String ks,String ck,String ts,String ct,String cfr) throws IOException
    {
		super(ss,ks,ck,ts,ct,cfr);
		this.docroot = docroot;
    }

    /**********************************************************
    * getBytes -- Retorna un array de bytes con el contenido del fichero. 
    *    representado por el argumento <b>path</b>.
    *
    *  @return the bytes for the file
    *  @exception FileNotFoundException si el fichero 
    *      <b>path</b> no existe
    *********************************************************/
    public byte[] getBytes(String path)  
    	                throws IOException, FileNotFoundException     {

	    String fichero = docroot + File.separator + path;

	    File f = new File(fichero);
		int length = (int)(f.length());

		System.out.println("leyendo: " + fichero);
		
		if (length == 0) {
		    throw new IOException("La longitud del fichero es cero: " + path);
		} 
		else 
		{
		    FileInputStream fin = new FileInputStream(f);
		    DataInputStream in  = new DataInputStream(fin);
	
		    byte[] bytecodes = new byte[length];
	
		    in.readFully(bytecodes);
		    return bytecodes;
		}
    }

    /** Main *********************************************
     * Main method to create the class server that reads
     * files. This takes two command line arguments, the
     * port on which the server accepts requests and the
     * root of the path. To start up the server: <
     *
     *   java ClassFileServer <port> <path>
     * 
     *
     * <code>   new ClassFileServer(port, docroot);
     * </code>
     *****************************************************/
    public static void main(String args[])
    {
		System.out.println(
		    "USAGE: java ClassFileServer port docroot [TLS [true]]");
		System.out.println("");
		System.out.println(
		    "If the third argument is TLS, it will start as\n" +
		    "a TLS/SSL file server, otherwise, it will be\n"   +
		    "an ordinary file server. \n"                      +
		    "If the fourth argument is true,it will require\n" +
		    "client authentication as well.");
	
		
	
		int port = DefaultServerPort;
	String 	keystorefile = args[0];
 	   String constrasenaKeystore =(args[1]);
 	   String truststore= args[2];
 	String  constrasenaTrustore=args[3];
  	  String opcion_cifrado=args[4];
  	definirKeyStores(keystorefile,constrasenaKeystore,truststore,constrasenaTrustore);
	
		try {
		    ServerSocketFactory ssf =
		    		ClassFileServer.getServerSocketFactory("TLS",keystorefile,constrasenaKeystore);
	
		    ServerSocket ss = ssf.createServerSocket(port);
		    docroot="~/workspace/seg/src/seg";
		   
		   ( (SSLServerSocket)ss).setNeedClientAuth(true);
		    new ClassFileServer(ss, docroot,keystorefile,constrasenaKeystore,truststore,constrasenaTrustore,opcion_cifrado);
		
		} catch (IOException e) {
		    System.out.println("Unable to start ClassServer: " +
				       e.getMessage());
		    e.printStackTrace();
		}
    }

    /******************************************************
    	getServerSocketFactory(String type) {}
    *****************************************************/
    private static ServerSocketFactory getServerSocketFactory(String type,String keystorefile, String constrasenaKeystore) {

    if (type.equals("TLS")) 
    {
    	SSLServerSocketFactory ssf = null;
	    
    	try {
			
    		// Establecer el keymanager para la autenticacion del servidor

    		SSLContext 			ctx;
			KeyManagerFactory 	kmf;
			KeyStore 			ks;
			char[] 				contraseña = constrasenaKeystore.toCharArray();
	
			ctx = SSLContext.getInstance("TLS");
			kmf = KeyManagerFactory.getInstance("SunX509");

			ks  = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(raiz + keystorefile), contraseña);

			kmf.init(ks, contraseña);
			
			ctx.init(kmf.getKeyManagers(), null, null);
	
			ssf = ctx.getServerSocketFactory();
			return ssf;
	    } 
	    catch (Exception e) {

	    	   e.printStackTrace();
	    }
	
    }  
    else 
    {
    	System.out.println("Usando la Factoria socket por defecto (no SSL)");

    	return ServerSocketFactory.getDefault();
	}
	
    return null;
    }

    /******************************************************
		definirKeyStores()
    *******************************************************/
	private static void definirKeyStores(String keystorefile, String constrasenaKeystore, String truststore, String constrasenaTrustore)
	{
		// Almacen de claves
		
		System.setProperty("javax.net.ssl.keyStore",         raiz +keystorefile);
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
	    System.setProperty("javax.net.ssl.keyStorePassword", constrasenaKeystore);
	
	    // Almacen de confianza
	    
	    System.setProperty("javax.net.ssl.trustStore",          raiz + truststore);
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
	    System.setProperty("javax.net.ssl.trustStorePassword", constrasenaTrustore);
	}
}



