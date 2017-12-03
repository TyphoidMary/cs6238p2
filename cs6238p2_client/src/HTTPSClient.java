/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author jdw6
 */
//public class HTTPSClient {   
//}
//basic server/client code from https://www.pixelstech.net/article/1445603357-A-HTTPS-client-and-HTTPS-server-demo-in-Java

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.sql.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import com.sun.org.apache.xml.internal.security.utils.Base64;
 
public class HTTPSClient {
    private String host = "127.0.0.1";
    //private String host = "172.16.16.99";
    private int port = 9999;
     
    public static void main(String[] args){
        HTTPSClient client = new HTTPSClient();
        client.run();
    }
     
    HTTPSClient(){      
    }
     
    HTTPSClient(String host, int port){
        this.host = host;
        this.port = port;
    }
     
    // Create the and initialize the SSLContext
    private SSLContext createSSLContext(){
        try{
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("keystore.jks"),"cs6238".toCharArray());
             
            // Create key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, "cs6238".toCharArray());
            KeyManager[] km = keyManagerFactory.getKeyManagers();
             
            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            
            KeyStore truststore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("truststore.jks"),"cs6238".toCharArray());
             
            trustManagerFactory.init(truststore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();
             
            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(km,  tm, null);
             
            return sslContext;
        } catch (Exception ex){
            ex.printStackTrace();
        }
         
        return null;
    }
     
    // Start to run the server
    public void run(){
        SSLContext sslContext = this.createSSLContext();
         
        try{
            // Create socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
             
            // Create socket
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.host, this.port);
             
            System.out.println("SSL client started");
            new ClientThread(sslSocket).start();
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }
     
    // Thread handling the socket to server
    static class ClientThread extends Thread {
        private SSLSocket sslSocket = null;
         
        ClientThread(SSLSocket sslSocket){
            this.sslSocket = sslSocket;
        }
         
        public void run(){
            
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
             
            try{
                // Start handshake
                sslSocket.startHandshake();
                
                 
                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();
                 
                System.out.println("SSLSession :");
                System.out.println("\tProtocol : "+sslSession.getProtocol());
                System.out.println("\tCipher suite : "+sslSession.getCipherSuite());
                System.out.println(sslSession.isValid());
                System.out.println("session ID: " + DatatypeConverter.printHexBinary(sslSession.getId()));
                
                string signedSessionID = signID(DatatypeConverter.printHexBinary(sslSession.getId()));
                // We have a signed session iD back (hopefully) Send it on the wire.
                
                
                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();
                 
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                 
                // Write data
                printWriter.println("Hello server this is client2");
                printWriter.println();
                printWriter.flush();
                 
                String line = null;
                while((line = bufferedReader.readLine()) != null){
                    System.out.println("Inut : "+line);
                     
                    if(line.trim().equals("HTTP/1.1 200\r\n")){
                        break;
                    }
                }
                 
                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        
        public string getUID()
        {
        	KeyStore client = KeyStore.getInstance("JKS");
		    client.load(new FileInputStream("C:\\Users\\Typhoidmary\\source\\Dev\\src\\dev\\user.jks"), "cs6238".toCharArray());
		    X509Certificate cert  = client.getCertificate("cs6238");
		    
		    return cert.getSerialNumber().toString();
		    
		    
        }
        
        public string signID(string SessionID) {
        	
        	try {
   		   
   		        
   		        KeyStore client = KeyStore.getInstance("JKS");
   		        client.load(new FileInputStream("C:\\Users\\Typhoidmary\\source\\Dev\\src\\dev\\user.jks"), "cs6238".toCharArray());
   		        
   		        				
   			        	Certificate cert  = client.getCertificate("cs6238");
   			        	PublicKey pub = cert.getPublicKey();
   			        	KeyPair kp = new KeyPair(pub, (PrivateKey) key);
   			        	String encodedKey = Base64.getEncoder().encodeToString(SessionID);
   			
   			            byte[] data = encodedKey.getBytes("UTF8");
   			
   			            Signature sig = Signature.getInstance("SHA1WithRSA");
   			            
   			            sig.initSign(kp.getPrivate());
   			            sig.update(data);
   			            byte[] signatureBytes = sig.sign();
   			            
   			
   			         
   			            
/***************************************************************************
 * This is the code to verify the signiture
 */
   			            sig.initVerify(cert);
   			            sig.update(data);
   			
   			            System.out.println(sig.verify(signatureBytes));
   			            if(sig.verify(signatureBytes)) {
   			            	return Base64.getEncoder().encode(signatureBytes));
   			            }else return null;
/*********   			          
 * End sig verification code
 */
   		        }catch (Exception ex) {
   		        	
   		        	System.out.println("Something went bang: " + ex.getMessage());
   		        	return null;
   		        }
        }
        public static string checkIn(File file, string sessionID) {
        	
        	Random rand = new Random();
    		 string fileID = (getUID() + (rand.nextInt(500000000) + 1).ToString());
    		 
    		 
    		 Base64.encode(new String(Files.readAllBytes(Paths.get(file.getPath()))).getBytes());
    		 
    		 return getUID() + ":" + sessionID + ":" + "CHECKIN" + ":" + "Placeholder Security attribute" + fileID + Base64.encode(new String(Files.readAllBytes(Paths.get(file.getPath()))).getBytes());
    		 
    		
    	}
    	
    	public static File checkOut(String fileName, SSLSocket http) {
    		File file;
    		FileOutputStream stream = null;
    		 
    		///Insert WS call here to populate the buffered reader
    		
    		while((line = bufferedReader.readLine()) != null){
    			string content = content + line;
             }
    		
    		file = new File(fileName);
    		
	            if(!file.exists()) {
	    	    	 file.createNewFile();
	    	     }
	            
            stream = new FileOutputStream(file);
            
            byte[] contentBytes = content.getGytes();
            
            stream.write(contentBytes);
            stream.flush();
            stream.close();
    	
    		return null;
    		
    	}
    	
    	public static void delegate(string fileID, string sessionID, String User, Date time, string permission)
    	{
    		return (getUID() + ":" + sessionID + ":" + "DELEGATE" + ":" + fileID + ":" + User + ":" + permission + ":" + time.toString())    		
    	}
    	
    	public static string delete(string fileID, string sessionID) {
    		
    		return (getUID() + ":" + sessionID + ":" + "DELETE" + fileID);
    		 
    	}
        
    }
}
