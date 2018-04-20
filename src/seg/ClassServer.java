
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.sql.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map.Entry;

import javax.security.auth.x500.X500Principal;
import javax.swing.text.html.HTMLDocument.Iterator;

/************************************************************
 * ClassServer.java -- a simple file server that can serve
 * Http get request in both clear and secure channel
 *
 *  Basado en ClassServer.java del tutorial/rmi
 ************************************************************/
public abstract class ClassServer implements Runnable {

    private ServerSocket server = null;
    private int idregistro= 1;
    String keystorefile=null;
    String constrasenaKeystore=null;
    String truststore= null;
   	String  constrasenaTrustore=null;
   	String algoritmo=null;
   	HashMap<Integer,ServidorRegistro> mapa=new HashMap<Integer,ServidorRegistro>();
    /**
     * Constructs a ClassServer based on <b>ss</b> and
     * obtains a file's bytecodes using the method <b>getBytes</b>.
     *
     */
    protected ClassServer(ServerSocket ss,String ks,String ck,String ts,String ct,String cifr)
    {
    		server = ss;
    		 keystorefile= ks;
    		 constrasenaKeystore=ck;
    		 truststore=ts;
    		 constrasenaTrustore= ct;
    		 algoritmo=cifr;
    		newListener();
    }

    /****************************************************************
     * getBytes -- Returns an array of bytes containing the bytes for
     * the file represented by the argument <b>path</b>.
     *
     * @return the bytes for the file
     * @exception FileNotFoundException if the file corresponding
     * to <b>path</b> could not be loaded.
     * @exception IOException if error occurs reading the class
     ***************************************************************/
    public abstract 
		    byte[] getBytes(String path)
		    			throws IOException, FileNotFoundException;

    /***************************************************************
     * run() -- The "listen" thread that accepts a connection to the
     * server, parses the header to obtain the file name
     * and sends back the bytes for the file (or error
     * if the file is not found or the response was malformed).
     **************************************************************/
    public void run()
    {
		Socket socket;
	
		// accept a connection
		try 
		{
		    socket = server.accept();
	
		} 
		catch (IOException e) {
		    System.out.println("Class Server died: " + e.getMessage());
		    e.printStackTrace();
		    return;
		}
	
		// create a new thread to accept the next connection
		newListener();

		try 
		{
			// Crea dos canales de salida, sobre el socket
			//		- uno binario  (rawOut)
			//		- uno de texto (out)
			String raiz="/home/juancho/seg/Servidor/";
			OutputStream rawOut = socket.getOutputStream();
			boolean correcto;
			ObjectOutputStream out= new ObjectOutputStream(socket.getOutputStream());
				    
		    try {
				// Obtener path to class file from header
		    	ServidorRegistro servidorR=new ServidorRegistro();
		    	ServidorRegistro servidorR2=new ServidorRegistro();
		    	
		    	
				ObjectInputStream in= new ObjectInputStream(socket.getInputStream());
				ClienteRegistro clienteR =(ClienteRegistro) in.readObject();
				int peticion=clienteR.getPeticion();
				switch( peticion){
				
				//*****************Registrar ***************************
				case 1: 
				String NombreDocumento =clienteR.getNombreDoc();
				String idPropietario=clienteR.getIdPropietario().toString();
				 byte[]  Document=clienteR.getDocument();
				 File ficherosalida=new File(raiz+NombreDocumento);
				 FileOutputStream fos = new FileOutputStream(ficherosalida);
				 fos.write(Document);
				 fos.close();
				 FileInputStream documento=new FileInputStream(raiz+NombreDocumento);
				 byte[] firmaDoc =clienteR.getFirmaDoc();
				 FirmaAsimetricaKeyStore firmarCliente = new FirmaAsimetricaKeyStore();
				 if(idPropietario.equals("CN=uvigo, C=ES")){
				   correcto=firmarCliente.Verificar(firmaDoc,documento,truststore,constrasenaTrustore,"certificadocliente");
				 }
				 else{
				   correcto=firmarCliente.Verificar(firmaDoc,documento,truststore,constrasenaTrustore,"certificadocliente2");
				 }
				 if(correcto){
				DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
				Calendar cal = Calendar.getInstance();
				System.out.println(dateFormat.format(cal.getTime())); //2014/08/06 16:00:22
				System.out.println("El id es : "+idregistro);
				servidorR.setNombreDoc(NombreDocumento);
				servidorR.setIdregistro(idregistro);
				servidorR.setDocument(Document);
				servidorR.setFirmaDoc(firmaDoc);
				servidorR.setSellotemporal(dateFormat.format(cal.getTime()));
				byte[] firmaServidor=FirmarServidor(servidorR,keystorefile,constrasenaKeystore);
				servidorR.setFirmaServidor(firmaServidor);
				servidorR.setError(0);
				servidorR.setTipoConfidencialidad(clienteR.getTipoConfidencialidad());
				ficherosalida.delete();
				byte[] docyfirma=juntarDocumento(Document,firmaServidor);
		
				
				 
				if(clienteR.getTipoConfidencialidad().equals("privado")){
					fos=new FileOutputStream(raiz+"fichero_aux");
					 fos.write(docyfirma);
					 fos.close();
					CifradoSimetrico cifrador=new CifradoSimetrico();
					CifradoSimetrico.cifrar("fichero_aux", raiz, idregistro+"_"+idPropietario, algoritmo,idregistro);
					File ficheroaux=new File(raiz+"fichero_aux");
							ficheroaux.delete();
				
				}
				else {
					fos = new FileOutputStream(raiz+idregistro+"_"+idPropietario);
					 fos.write(docyfirma);
					 fos.close();
				}
				System.out.println((X500Principal) clienteR.getIdPropietario());
				servidorR.setIdPropietario((X500Principal) clienteR.getIdPropietario());
				mapa.put(idregistro, servidorR);
				idregistro++;
				ficherosalida.delete();
				 }
				 else {
					 servidorR.setError(1);
				 }
				break;
				
				//********************Recuperar*************************
				case 2:
					
					
					int id= clienteR.getIdregistro();
			   if( mapa.containsKey(id)){
				   servidorR2=mapa.get(id);
				   System.out.println((X500Principal) servidorR2.getIdPropietario());
				   if(servidorR2.getTipoConfidencialidad().equals("privado")){
					   if(servidorR2.getIdPropietario().toString().equals(clienteR.getIdPropietario().toString())){
						   CifradoSimetrico descifrador=new CifradoSimetrico();
							CifradoSimetrico.descifrar("fichero_aux", raiz, id+"_"+servidorR2.getIdPropietario().toString(), algoritmo,id);
							FileInputStream inputaux=new FileInputStream(raiz+"fichero_aux");
							byte[] docyfirma2= FiletoArray(inputaux);
							byte[] doc2= separar(docyfirma2);
							servidorR = new ServidorRegistro();
							servidorR.setDocument(doc2);
							servidorR.setIdregistro(id);
							servidorR.setFirmaServidor(servidorR2.getFirmaServidor());
							servidorR.setSellotemporal(servidorR2.getSellotemporal());
							servidorR.setNombreDoc(servidorR2.getNombreDoc());
							servidorR.setFirmaDoc(servidorR2.getFirmaDoc());
							servidorR.setError(0);
							File ficheroaux=new File(raiz+"fichero_aux");
							ficheroaux.delete();
					   }
					   else{
						   servidorR.setError(3);
					   }
				   }
				   else {     //Es  publico 
					   FileInputStream inputaux=new FileInputStream(raiz+ id+"_"+servidorR2.getIdPropietario());
						byte[] docyfirma2= FiletoArray(inputaux);
						byte[] doc2= separar(docyfirma2);
						servidorR = new ServidorRegistro();
						servidorR.setDocument(doc2);
						servidorR.setIdregistro(id);
						servidorR.setFirmaServidor(servidorR2.getFirmaServidor());
						servidorR.setSellotemporal(servidorR2.getSellotemporal());
						servidorR.setNombreDoc(servidorR2.getNombreDoc());
						servidorR.setFirmaDoc(servidorR2.getFirmaDoc());
						servidorR.setError(0);
					   
				   }
			   }
			   else {
				   servidorR.setError(2);
				   
			   }
				break;
				//*************************Lista*******************
				case 3:
					
					ArrayList<String> ListaDocPublicos= new ArrayList<String>();
			        ArrayList<String> ListaDocPrivados= new ArrayList<String>();
			     String   idPropetario=  clienteR.getIdPropietario().toString();
			     
					     
					        for (ServidorRegistro value : mapa.values()) {
					        
					            if (value.getTipoConfidencialidad().equals("privado")){
					            if (idPropetario.equals(value.getIdPropietario().toString())){
					 
					                ListaDocPrivados.add(value.getIdregistro()+" "+value.getNombreDoc()+" "+value.getSellotemporal());
					            	}
					            }
					            else{   
					                ListaDocPublicos.add(value.getIdregistro()+" "+value.getNombreDoc()+" "+value.getSellotemporal());
					            }
					        }
					        servidorR.setListarDocumentosPublicos(ListaDocPublicos);
					        servidorR.setListarDocumentosPrivate(ListaDocPrivados);
					        servidorR.setError(0);
					
					break;
				
				}
				try 
				{
					
					out.writeObject(servidorR);
				} 
				catch (IOException ie) {
				    ie.printStackTrace();
				    return;
				}
	
		    } 
		    catch (Exception e) {
				e.printStackTrace();
				// write out error response
				
		    }
	
		} catch (IOException ex) {
		    // eat exception (could log error to log file, but
		    // write out to stdout for now).
		    System.out.println("error writing response: " + ex.getMessage());
		    ex.printStackTrace();
	
		} finally {
		    try {
			socket.close();
		    } catch (IOException e) {
		    }
		}
    }

    /********************************************************
     * newListener()
     * 			Create a new thread to listen.
     *******************************************************/
    private void newListener()
    {
    	(new Thread(this)).start();
    }

    /*******************************************************
     * 	obtenerPath 
     * 			Returns the path to the file obtained from
     * 			parsing the HTML header.
     *******************************************************/
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
    static byte[] FirmarServidor(ServidorRegistro servidorR,String keystorefile, String constrasenaKeystore)throws  IOException {
    try{	
    	byte[] idregistro = ByteBuffer.allocate(4).putInt(servidorR.getIdregistro()).array();
		byte[] document= servidorR.getDocument();
		byte[] firmadoc =servidorR.getFirmaDoc();
		byte[] sello =servidorR.getSellotemporal().getBytes();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write( idregistro );
		outputStream.write( document );
		outputStream.write( firmadoc);
		outputStream.write( sello );

		byte c[] = outputStream.toByteArray( );
		FileOutputStream fos = new FileOutputStream("fichero_aux");
		 fos.write(c);
		 fos.close();
		 FileInputStream documento=new FileInputStream("fichero_aux");
		 FirmaAsimetricaKeyStore firmarCliente=new FirmaAsimetricaKeyStore();
		byte[] firma=firmarCliente.Firmar("fichero_aux",keystorefile,constrasenaKeystore,"claveservidor");
		return firma; 
    }
    catch(Exception e){
    	e.printStackTrace();
    	return null;
    }
    }
    byte[] juntarDocumento(byte[] Document,byte[]firma)throws  IOException {
    	ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write( Document );
	
		byte[] d="separador".getBytes();
		outputStream.write( d );
		outputStream.write( firma );
		byte c[] = outputStream.toByteArray( );
		return c;
    }
    byte[] separar(byte[] docyfirma){
    	byte[] d="separador".getBytes();
    	KPM KPM1= new KPM();
		int i=KPM.indexOf(docyfirma,d);
		byte doc[]=new byte[i];
		for(int j=0;j<i;j++){
			doc[j]=docyfirma[j];
		}
		return doc;
    }

}
