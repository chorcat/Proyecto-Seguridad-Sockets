

import java.io.FileInputStream;
import java.io.Serializable;
import java.util.ArrayList;

import javax.security.auth.x500.X500Principal;

public class ServidorRegistro  implements Serializable {
	public ServidorRegistro() {
		super();
	}
	private String nombreDoc;
	private byte[]  Document;
	private String tipoConfidencialidad;
	private byte[] firmaDoc;
	private X500Principal idPropietario;
	private String sellotemporal; 
	private int Idregistro;
	private byte[] firmaServidor;
	private ArrayList<String>  listarDocumentosPublicos;
	private ArrayList<String>  listarDocumentosPrivate;
	private int error;
 	public String getNombreDoc() {
		return nombreDoc;
	}
	public void setNombreDoc(String nombreDoc) {
		this.nombreDoc = nombreDoc;
	}
	public byte[] getDocument() {
		return Document;
	}
	public void setDocument(byte[]  document) {
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
	public String getSellotemporal() {
		return sellotemporal;
	}
	public void setSellotemporal(String sellotemporal) {
		this.sellotemporal = sellotemporal;
	}
	public int getIdregistro() {
		return Idregistro;
	}
	public void setIdregistro(int idregistro) {
		Idregistro = idregistro;
	}
	public byte[] getFirmaServidor() {
		return firmaServidor;
	}
	public void setFirmaServidor(byte[] firmaServidor) {
		this.firmaServidor = firmaServidor;
	}
	public ArrayList<String>  getListarDocumentosPublicos() {
		return listarDocumentosPublicos;
	}
	public void setListarDocumentosPublicos(ArrayList<String> listarDocumentos) {
		this.listarDocumentosPublicos = listarDocumentos;
	}
	public int getError() {
		return error;
	}
	public void setError(int error) {
		this.error = error;
	}
	public ArrayList<String> getListarDocumentosPrivate() {
		return listarDocumentosPrivate;
	}
	public void setListarDocumentosPrivate(ArrayList<String> listarDocumentosPrivate) {
		this.listarDocumentosPrivate = listarDocumentosPrivate;
	}
}
