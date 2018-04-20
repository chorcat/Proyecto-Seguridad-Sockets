import java.io.File;
import java.io.FileInputStream;
import java.io.Serializable;

import javax.security.auth.x500.X500Principal;

public class ClienteRegistro  implements Serializable {
   /**
	 * 
	 */

public ClienteRegistro() {
		super();
		// TODO Auto-generated constructor stub
	}
private String nombreDoc;
	private byte[] Document;
	private String tipoConfidencialidad;
	private byte[] firmaDoc;
	private X500Principal idPropietario;
	private int peticion;
	private int Idregistro;
	public String getNombreDoc() {
		return nombreDoc;
	}
	public void setNombreDoc(String nombreDoc) {
		this.nombreDoc = nombreDoc;
	}
	public byte[]  getDocument() {
		return Document;
	}
	public void setDocument(byte[] document) {
		Document = document;
	}
	public String getTipoConfidencialidad() {
		return tipoConfidencialidad;
	}
	public void setTipoConfidencialidad(String tipoConfidencialidad) {
		this.tipoConfidencialidad = tipoConfidencialidad;
	}
	public byte[] getFirmaDoc() {
		return firmaDoc;
	}
	public void setFirmaDoc(byte[] firmaDoc) {
		this.firmaDoc = firmaDoc;
	}
	public Object getIdPropietario() {
		return idPropietario;
	}
	public void setIdPropietario(X500Principal idPropietario) {
		this.idPropietario = idPropietario;
	}
	public int getPeticion() {
		return peticion;
	}
	public void setPeticion(int peticion) {
		this.peticion = peticion;
	}
	public int getIdregistro() {
		return Idregistro;
	}
	public void setIdregistro(int idregistro) {
		Idregistro = idregistro;
	}
}
