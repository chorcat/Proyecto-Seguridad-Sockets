

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
//
//


public class FirmaAsimetricaKeyStore {

    public FirmaAsimetricaKeyStore() {
		super();
		// TODO Auto-generated constructor stub
	}


	  byte[] Firmar(String ruta,String keyStore,String contrasena,String entry ) throws SignatureException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, IOException, UnrecoverableEntryException { 
		String  directorioRaiz="/home/juancho/seg/";
    	
    	FileInputStream fmensaje   = new    FileInputStream(ruta); 

    String 		provider         = "SunJCE"; 
    String 		algoritmo        =  "SHA1withRSA"; 
    String 		algoritmo_base   =  "RSA";    
    int    		longitud_clave   =  2048;         
    int    		longbloque;
    byte   		bloque[]         = new byte[2048];
    long   		filesize         = 0;
    
    // Variables para el KeyStore

	KeyStore    ks;
	char[]      ks_password  	= contrasena.toCharArray();
	char[]      key_password 	= contrasena.toCharArray();
	String		ks_file			= directorioRaiz + keyStore;	    
    
    
    // Obtener la clave privada del keystore
 			
	ks = KeyStore.getInstance("JCEKS");

	ks.load(new FileInputStream(ks_file),  ks_password);

	KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
 	      		   						ks.getEntry(entry, 
                                        new KeyStore.PasswordProtection(key_password)); //clavecliente
 
    PrivateKey privateKey = pkEntry.getPrivateKey();
    
	System.out.println("************************************* ");
	System.out.println("***             FIRMA             *** ");
	System.out.println("************************************* ");

    // Visualizar clave privada
	System.out.println("*** CLAVE PRIVADA ***");	System.out.println(privateKey);

	// Creamos un objeto para firmar/verificar
	
    Signature signer = Signature.getInstance(algoritmo);

    // Inicializamos el objeto para firmar
    signer.initSign(privateKey);
	
	// Para firmar primero pasamos el hash al mensaje (metodo "update")
    // y despues firmamos el hash (metodo sign).

    byte[] firma = null;
	
    while ((longbloque = fmensaje.read(bloque)) > 0) {
        filesize = filesize + longbloque;    		     
    	signer.update(bloque,0,longbloque);
    }  

    firma = signer.sign();
	
	double  v = firma.length;
	
	System.out.println("*** FIRMA: ****");
	for (int i=0; i<firma.length; i++)
	
		System.out.print(firma[i] + " ");
	System.out.println();
	System.out.println();

	fmensaje.close();
	return firma;
    }
	
    
	/*******************************************************************
	 *       Verificacion
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 ******************************************************************/
   boolean  Verificar(byte[] firma,FileInputStream fmensajeV,String keyStore,String contrasena, String entry ) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException{
	System.out.println("************************************* ");
	System.out.println("    VERIFICACION                    * ");
	System.out.println("************************************* ");
    String 		provider         = "SunJCE"; 
    String 		algoritmo        =  "SHA1withRSA"; 
    String 		algoritmo_base   =  "RSA";    
    int    		longitud_clave   =  2048;         
    int    		longbloque;
    byte   		bloque[]         = new byte[2048];
    long   		filesize         = 0;

	KeyStore    ks;
	char[]      ks_password  	= contrasena.toCharArray();
	char[]      key_password 	= contrasena.toCharArray();
	String		ks_file			=  "/home/juancho/seg/"+keyStore;	    //Hay que cambiar esto 
    
    
    // Obtener la clave privada del keystore
 			
	ks = KeyStore.getInstance("JCEKS");

	ks.load(new FileInputStream(ks_file),  ks_password);
    

	

	// Creamos un objeto para verificar
	Signature verifier=Signature.getInstance(algoritmo);	 
	KeyStore ks1 = KeyStore.getInstance("JCEKS");
	ks_file="/home/juancho/seg/"+keyStore;
	ks_password  = contrasena.toCharArray();
	ks1.load(new FileInputStream(ks_file),  ks_password);

    // Obtener la clave publica del keystore
   // PublicKey   publicKey  = ks.getCertificate("clavecliente").getPublicKey();
    PublicKey   publicKey  =ks1.getCertificate(entry).getPublicKey();
    System.out.println("*** CLAVE PUBLICA ***");	System.out.println(publicKey);
	
    // Obtener el usuario del Certificado tomado del KeyStrore
    byte []   certificadoRaw  = ks1.getCertificate(entry ).getEncoded(); //certificadocliente
    
    ByteArrayInputStream inStream = null;

    inStream = new ByteArrayInputStream(certificadoRaw);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
    System.out.println ("Usuario certificado " + 
		   						cert.getIssuerX500Principal());       
       
    // Inicializamos el objeto para verificar
	
    verifier.initVerify(publicKey);
    
    while ((longbloque = fmensajeV.read(bloque)) > 0) {
        filesize = filesize + longbloque;    		     
    	verifier.update(bloque,0,longbloque);
    }  

	boolean resultado = false;
	
	resultado = verifier.verify(firma);
	
	System.out.println();
	if (resultado == true){ 
	    System.out.println("Firma CORRECTA");
	    fmensajeV.close();
	return true;
	}
	else{
		System.out.println("Firma NO correcta");	
		fmensajeV.close();
	return false;
	}
	


    }
}

