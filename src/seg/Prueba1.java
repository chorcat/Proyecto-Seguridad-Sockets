package seg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Prueba1 {

	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		byte[] a ="hola soy juan".getBytes();
		System.out.println("La longitud de a: "+a.length);
		byte[] b =" hola soy pepe".getBytes();
		byte[] d="separador".getBytes();
		System.out.println("La longitud de d: "+d.length);
		System.out.println("La longitud de b: "+b.length);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

		outputStream.write( a );
		outputStream.write( d);
		outputStream.write( b);
		String hola=new String(a);
		System.out.println(hola);
	
		byte c[] = outputStream.toByteArray( );
		System.out.println("La longitud de c: "+c.length);
		KPM KPM1= new KPM();
		int i=KPM1.indexOf(c,d);
		byte h[]=new byte[c.length];
		int iterador=0;
		for(int j=i+d.length;j<c.length;j++){
			h[iterador]=c[j];
			iterador++;
		}
		System.out.println(new String(h));
		System.out.println("Es "+i);
		
	}

}
