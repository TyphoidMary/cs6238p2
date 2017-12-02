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
 
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
 
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
            trustManagerFactory.init(keyStore);
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
        
        public bool login(SSLSocket sckt) {
        	
        	
        }
        public static void checkIn(File file, SSLSocket http) {
    		
    		
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
    	
    	public static void delegate(int fileID, String User, Date time, SSLSocket http)
    	{
    		
    		
    	}
    	
    	public static boolean delete(int fileID, String User) {
    		
    		String jsonText = String.format("{\"user\":\"{0}\",\"fileID\":\"{1}\"}", User, fileID);
    		CkHttpResponse response = http.PostJson("https://project.local/endpoint/delete", jsonText);
    		 
    		CkJsonObject responseBody = new CkJsonObject();
     		responseBody.Load(response.bodyStr());
     		CkJsonObject confirmation = responseBody.FindObjectWithMember("deleted");
     		if(confirmation != null) {
     			return true; 			
     		}else {
     			return false;
     		}
    		 
    	}
    	
    	public static void endSession() {
    		this.sslSocket.

    	}
        
    }
}
