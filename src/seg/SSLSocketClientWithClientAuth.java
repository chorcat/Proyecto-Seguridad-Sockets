
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.security.auth.x500.X500Principal;

/****************************************************************************
* This example shows how to set up a key manager to do client
* authentication if required by server.
*
* This program assumes that the client is not inside a firewall.
* The application can be modified to connect to a server outside
* the firewall by following SSLSocketClientWithTunneling.java.
* 
****************************************************************************/
public class SSLSocketClientWithClientAuth {

	private static String 	raizMios =    "/home/juancho/seg/Cliente/";

	public static void main(String[] args) throws Exception {
	   String keystorefile=null;
	   String constrasenaKeystore=null;
	   String truststore=null;
	   String constrasenaTrustore=null;
	   String opcion=null;
	   String privacidad=null;
       String 	host 		= "localhost";
       int idregistro=1;
       int 		port 		= 9001;
       String 	path 		= null;
       char[] 	contraseña 		  = "123456".toCharArray();
       char[] 	contraseñaEntrada = "1234567".toCharArray();
     
	 

       for (int i = 0; i < args.length; i++)
           System.out.println(args[i]);

       if (args.length < 5) {
           System.out.println(
               "USAGE: java SSLSocketClientWithClientAuth " +
               "keystorefile constraseñakeystore truststore constraseñaTrustore opcion");
           System.exit(-1);
       }

       try {
    	   keystorefile = args[0];
    	   constrasenaKeystore =(args[1]);
    	   truststore= args[2];
    	   constrasenaTrustore=args[3];
    	   opcion=args[4];
    	   if(opcion.equals("registrar")){
    		   path=args[5];
    		   privacidad=args[6];
    		   
    	   }
    	   if(opcion.equals("recuperar")){
    		 idregistro=Integer.parseInt(args[5]);
    		   
    	   }
    	   definirKeyStores(keystorefile,constrasenaKeystore,truststore,constrasenaTrustore);
    	   
       } catch (IllegalArgumentException e) {
            System.out.println("USAGE: java SSLSocketClientWithClientAuth " +
                "host port requestedfilepath");
            System.exit(-1);
       }

       try {

           /*****************************************************************************
            * Set up a key manager for client authentication if asked by the server.  
            * Use the implementation's default TrustStore and secureRandom routines.
            ****************************************************************************/
           SSLSocketFactory factory = null;
           try {
               SSLContext 			ctx;
               KeyManagerFactory 	kmf;
               KeyStore 			ks;

               ctx = SSLContext.getInstance("TLS");
               kmf = KeyManagerFactory.getInstance("SunX509");
               ks = KeyStore.getInstance("JCEKS");

   			   ks.load(new FileInputStream(raizMios + "keystoreCliente.jce"), contraseña);

               kmf.init(ks, contraseña);
               
               ctx.init(kmf.getKeyManagers(), null, null);

               factory = ctx.getSocketFactory();

              	/*********************************************************************
              	 * Suites SSL del contexto
              	 *********************************************************************/
	   	   	    // Suites disponibles
	   	
	   	   	    System.out.println ("******** CypherSuites Disponibles **********");
	   	
	   	   	    String[] cipherSuites = factory.getSupportedCipherSuites();
	   	   	    for (int i=0; i<cipherSuites.length; i++) 
	   	       		System.out.println (cipherSuites[i]);	    
	   	
	   	   	    // Suites habilitadas por defecto
	   	
	   	   	    System.out.println ("****** CypherSuites Habilitadas por defecto **********");
	   	   	    
	   	   	    String[] cipherSuitesDef = factory.getDefaultCipherSuites();
	   	   	    for (int i=0; i<cipherSuitesDef.length; i++) 
	   	       		System.out.println (cipherSuitesDef[i]);

           
           } catch (Exception e) {
               throw new IOException(e.getMessage());
           }

           SSLSocket socket = (SSLSocket)factory.createSocket(host, port);


           /*********************************************************************
            * send http request
            *
            * See SSLSocketClient.java for more information about why
            * there is a forced handshake here when using PrintWriters.
            ********************************************************************/

   	    
	   	    System.out.println ("Comienzo SSL Handshake -- Cliente y Server Autenticados");
	
	   	    socket.startHandshake();	    
	   	    
	   	    System.out.println ("Fin OK SSL Handshake");
           
	   	 ObjectOutputStream out= new ObjectOutputStream(socket.getOutputStream());
	   	ObjectInputStream in= new ObjectInputStream(socket.getInputStream());
	   //	String tipo ="publico";
	   	if(opcion.equals("registrar")){
	   	Registrar_documento(in,out,keystorefile,constrasenaKeystore,path,privacidad);
	   	}
	   	if(opcion.equals("recuperar")){
		   	Recuperar_documento(in,out,keystorefile,constrasenaKeystore,idregistro);
		   	}
	   	if(opcion.equals("listar")){
		   	Listar_documento(in,out,keystorefile,constrasenaKeystore);
		   	}


           in.close();
           out.close();
           socket.close();

       } catch (Exception e) {
           e.printStackTrace();
       }
   }

   /******************************************************
		definirKeyStores()
   *******************************************************/
	private static void definirKeyStores(String keystorefile, String constrasenaKeystore, String truststore, String constrasenaTrustore)
	{
	
		String 	raiz = "/home/seg/Servidor/";

		// Almacen de claves		
		
		System.setProperty("javax.net.ssl.keyStore",         raiz + "testkeys.jce");
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
	    System.setProperty("javax.net.ssl.keyStorePassword", "passphrase");
	
	    // Almacen de confianza
	    
	    System.setProperty("javax.net.ssl.trustStore",          raiz + "samplecacerts.jce");
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
	    System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
 
	    
		// ----  Almacenes mios  -----------------------------
		
		// Almacen de claves

System.out.println("---------------------------------Hola estoy aqui");
		
		System.setProperty("javax.net.ssl.keyStore",         raizMios + keystorefile);
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
	    System.setProperty("javax.net.ssl.keyStorePassword", constrasenaKeystore);
	
	    // Almacen de confianza
	    
	    System.setProperty("javax.net.ssl.trustStore",          raizMios +  truststore);
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
	    System.setProperty("javax.net.ssl.trustStorePassword", constrasenaTrustore);
	

	}
static byte[]  FiletoArray(FileInputStream fis) throws  IOException {
	      
	        ByteArrayOutputStream bos = new ByteArrayOutputStream();
	        byte[] buf = new byte[1024];
	        try {
	            for (int readNum; (readNum = fis.read(buf)) != -1;) {
	                bos.write(buf, 0, readNum); //no doubt here is 
	              
	            }
	        } catch (IOException ex) {
	            
	        }
	        byte[] bytes = bos.toByteArray();
	        return bytes;
	        //below is the different part
	     
	    }
static boolean VerificaServidor(ServidorRegistro servidorR,String keystorefile, String constrasenaKeystore){ //El keystore hace de trustore en este caso
	try{
	byte[] idregistro = ByteBuffer.allocate(4).putInt(servidorR.getIdregistro()).array();
	byte[] document= servidorR.getDocument();
	byte[] firmadoc =servidorR.getFirmaDoc();
	byte[] sello =servidorR.getSellotemporal().getBytes();
	byte[] firma=servidorR.getFirmaServidor();
	ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
	outputStream.write( idregistro );
	outputStream.write( document );
	outputStream.write( firmadoc);
	outputStream.write( sello );

	byte c[] = outputStream.toByteArray( );
	FileOutputStream fos = new FileOutputStream("fichero_aux2");
	 fos.write(c);
	 fos.close();
	 FileInputStream documento=new FileInputStream("fichero_aux2");
	 FirmaAsimetricaKeyStore VerificarServidor=new FirmaAsimetricaKeyStore();
	boolean correcto=VerificarServidor.Verificar(firma,documento,keystorefile,constrasenaKeystore,"certificadoservidor");
	return correcto;
	}
	catch(Exception e){
		 e.printStackTrace();
		return false;
	}
}

static void Registrar_documento(ObjectInputStream in,ObjectOutputStream out,String keystorefile, String constrasenaKeystore,String path,String privacidad )throws Exception {
	byte[] firma;  
	String  nombreDocumento=path;
	   	System.out.println("El nombre del documento es "+nombreDocumento);
	   	FirmaAsimetricaKeyStore firmarCliente = new FirmaAsimetricaKeyStore();
	   	try{
	   	 firma=firmarCliente.Firmar("/home/juancho/seg/Cliente/"+path,keystorefile,constrasenaKeystore,"clavecliente");
	   	}
	   	catch(NullPointerException e){
	   		firma=firmarCliente.Firmar("/home/juancho/seg/Cliente/"+path,keystorefile,constrasenaKeystore,"clavecliente2");
		}
	   	    ClienteRegistro clienteR =new ClienteRegistro();
	   	    clienteR.setNombreDoc(nombreDocumento);
	   	 clienteR.setFirmaDoc(firma);
	   	FileInputStream fmensaje   = new    FileInputStream("/home/juancho/seg/Cliente/"+path);
	   	byte[] Document=FiletoArray(fmensaje);
	   	clienteR.setDocument(Document );
	   	
	    System.out.println("IDautor  : "+Idcliente( keystorefile,  constrasenaKeystore));
	    clienteR.setIdPropietario(Idcliente( keystorefile,  constrasenaKeystore));
	    clienteR.setTipoConfidencialidad(privacidad);
	    clienteR.setPeticion(1);
	   	 out.writeObject(clienteR); //Enviar el objeto
	   	 
	   	ServidorRegistro servidorR =(ServidorRegistro) in.readObject();
	   	if(servidorR.getError()==0){
		if(VerificaServidor( servidorR,keystorefile,constrasenaKeystore)){
			MessageDigest dg =MessageDigest.getInstance("SHA-256");
			byte[] hashDoc=dg.digest(Document);
			File ficheroaux=new File("/home/juancho/seg/Cliente/"+nombreDocumento);
			FileOutputStream fuera= new FileOutputStream(ficheroaux);
			fuera.write(hashDoc);
			fuera.close();
			System.out.println("Documento correctamente registrado, con id "+servidorR.getIdregistro());
			}
		else {
			System.out.println("La firma que presenta el servidor no es correcta ");
		}
	   	}
	   	else{
	   		System.out.println("Se ha producido el error: "+getStringError(servidorR.getError()));
	   	}
}
static void Recuperar_documento(ObjectInputStream in,ObjectOutputStream out,String keystorefile, String constrasenaKeystore,int idregistro )throws Exception {
	 ClienteRegistro clienteR =new ClienteRegistro();
	 clienteR.setPeticion(2);
	 clienteR.setIdregistro(idregistro);
	 clienteR.setIdPropietario(Idcliente( keystorefile,  constrasenaKeystore));
	 out.writeObject(clienteR); 
	 ServidorRegistro servidorR =(ServidorRegistro) in.readObject();
	   	if(servidorR.getError()==0){
	   		if(VerificaServidor( servidorR,keystorefile,constrasenaKeystore)){
	   		byte[] doc =servidorR.getDocument();
	   		
			FileInputStream  filehash       = new FileInputStream ("/home/juancho/seg/Cliente/"+servidorR.getNombreDoc());
			 byte[]        hash =FiletoArray(filehash);
			 MessageDigest dg =MessageDigest.getInstance("SHA-256");
				byte[] hashDoc=dg.digest(doc);
				if (Arrays.equals(hashDoc, hash)){
					File ficheroaux=new File("/home/juancho/seg/Cliente/"+servidorR.getNombreDoc()); //servidorR.getNombreDoc()
					FileOutputStream fuera= new FileOutputStream(ficheroaux);
					fuera.write(doc);
					fuera.close();
			System.out.println("Documento correctamente recuperado, con id "+servidorR.getIdregistro());
				}
				else {
					File ficheroaux=new File("/home/juancho/seg/Cliente/documentoalterado"); //servidorR.getNombreDoc()
					FileOutputStream fuera= new FileOutputStream(ficheroaux);
					fuera.write(doc);
					fuera.close();
					System.out.println("Documento alterado por el registrador");
				}
	   	}
	   		else {
	   			System.out.println("La firma que presenta el servidor no es correcta ");
	   	}
	   		
	   	}
	   	else {
	   		System.out.println("Se ha producido el error: "+getStringError(servidorR.getError()));
	   	}
}

static void Listar_documento(ObjectInputStream in,ObjectOutputStream out,String keystorefile, String constrasenaKeystore )throws Exception{
	ClienteRegistro clienteR =new ClienteRegistro();
	 clienteR.setPeticion(3);
	 clienteR.setIdPropietario(Idcliente( keystorefile,  constrasenaKeystore));
	 out.writeObject(clienteR); 
	 ServidorRegistro servidorR =(ServidorRegistro) in.readObject();
	   	if(servidorR.getError()==0){
	   		ArrayList<String> ListaDocPublicos= servidorR.getListarDocumentosPublicos();
	        ArrayList<String> ListaDocPrivados= servidorR.getListarDocumentosPrivate();
	        System.out.println("Documentos publicos");
	        if(ListaDocPublicos.isEmpty()){
	        	System.out.println("Vacio");
	        }
	        for(int i=0;i<ListaDocPublicos.size();i++){
	        	System.out.println(ListaDocPublicos.get(i));
	        }
	        System.out.println("Documentos privados");
	        if(ListaDocPublicos.isEmpty()){
	        	System.out.println("Vacio");
	        }
	        for(int i=0;i<ListaDocPrivados.size();i++){
	        	System.out.println(ListaDocPrivados.get(i));
	        }
	   	}
}

static X500Principal Idcliente(String keystorefile, String constrasenaKeystore)throws Exception{
	byte []   certificadoRaw;
		KeyStore ks = KeyStore.getInstance("JCEKS");
		String ks_file = raizMios +keystorefile;
		char[] ks_password = constrasenaKeystore.toCharArray();
		ks.load(new FileInputStream(ks_file),  ks_password);
		try{
	   	  certificadoRaw  = ks.getCertificate("clavecliente").getEncoded();
		}
		catch(NullPointerException e){
			certificadoRaw  = ks.getCertificate("clavecliente2").getEncoded();
		}
	    ByteArrayInputStream inStream = null;
	    inStream = new ByteArrayInputStream(certificadoRaw);
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
	    return cert.getIssuerX500Principal();
}

static String getStringError(int e){
	switch(e){
	case 1 : 
		return "La firma del cliente no es correcta";
	
	case 2 : 
		return "Documento no existente";
		
	case 3 :
		return "Acceso no permitido";

	}
	return "Error"+e;
	}
}
