package cs6238p2_client.src;

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
import java.io.FileInputStream;
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
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Base64;

public class HTTPSClient {

    private String host = "127.0.0.1";
    //private String host = "172.16.16.99";
    private int port = 9999;
    private String[] args;

    public static void main(String[] args) {
        HTTPSClient client = new HTTPSClient(args);
        client.run();
    }

    HTTPSClient(String[] args) {
    	this.args = args;
    }

    HTTPSClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    // Create the and initialize the SSLContext
    private SSLContext createSSLContext() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("C:\\Users\\Typhoidmary\\source\\Dev\\src\\dev\\keystore.jks"), "cs6238".toCharArray());

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
            sslContext.init(km, tm, null);

            return sslContext;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    // Start to run the server
    public void run() {
        SSLContext sslContext = this.createSSLContext();

        try {
            // Create socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Create socket
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.host, this.port);

            System.out.println("SSL client started");
            new ClientThread(sslSocket, args).start();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // Thread handling the socket to server
    static class ClientThread extends Thread {
    	private String[] args;
        private SSLSocket sslSocket = null;

        ClientThread(SSLSocket sslSocket, String[] args) {
            this.sslSocket = sslSocket;
            this.args = args;
        }

        public void run() {

            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                // Start handshake
                sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                System.out.println("SSLSession :");
                System.out.println("\tProtocol : " + sslSession.getProtocol());
                System.out.println("\tCipher suite : " + sslSession.getCipherSuite());
                System.out.println(sslSession.isValid());
                //get ssl sesison id
                System.out.println("session ID: " + DatatypeConverter.printHexBinary(sslSession.getId()));
                String signedSessionID = signID(DatatypeConverter.printHexBinary(sslSession.getId()));
                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                
                printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":CHECKIN:CONFIDENTIALITY:abb4ef42211b4720:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");

                /*
                if(this.args[0].equals("CHECKIN")) {
                	
                	if(this.args[1].equals("CONFIDENTIALITY")) {
	                	// Write data
	                    //printWriter.println("userID:signed_sessionId:CHECKIN:security_flag:file_ID:base64_encoded_File");
	                    //checkin encrypt
	                    printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":CHECKIN:CONFIDENTIALITY:abb4ef42211b4720:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");
                	}
                	else if(this.args[1].equals("INTEGRITY")) {
                		printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":CHECKIN:INTEGRITY:baa4ef42211b5619:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");
                	}
                	else if(this.args[1].equals("none") || this.args[1].isEmpty()) {
                		printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":CHECKIN:NONE:abb4ef42211b3685:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");
                	}
                }else if(this.args[0].equals("CHECKOUT")) {
                	
                	//checkout encrypted doc
                    printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":CHECKOUT:abb4ef42211b4720");
                	
                }else if (this.args[0].equals("DELETE")) {
                	 
                	printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":DELETE:abb4ef42211b4720");
                	
                }else if (this.args[0].equals("DELEGATE")) {
                	
                	if(args[2].equals("OWNER")) {
                		printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":DELEGATE:abb4ef42211b4720:f9b4ef92212b8741:OWNER:600");
                	} else if(args[2].equals("CHECKIN")) {
                		printWriter.println("f9b4ef92212b8740:" + signedSessionID + ":DELEGATE:abb4ef42211b4720:f9b4ef92212b8743:CHECKIN:600");
                	}
                	
                }
                /*
                // Write data
                //printWriter.println("userID:signed_sessionId:CHECKIN:security_flag:file_ID:base64_encoded_File");
                //checkin encrypt
                printWriter.println("f9b4ef92212b8740:signed_sessionId:CHECKIN:CONFIDENTIALITY:abb4ef42211b4720:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");
                //checkout encrypted doc
                printWriter.println("f9b4ef92212b8740:signed_sessionId:CHECKOUT:abb4ef42211b4720");
                //checkin using del priv
                //printWriter.println("f9b4ef92212b8743:signed_sessionId:CHECKIN:CONFIDENTIALITY:abb4ef42211b4720:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");
                //checkin a doc with integeity
                //printWriter.println("f9b4ef92212b8740:signed_sessionId:CHECKIN:INTEGRITY:baa4ef42211b5619:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");
                //printWriter.println("f9b4ef92212b8740:signed_sessionId:CHECKIN:NONE:abb4ef42211b3685:dGhpcyBpcyBhIHRlc3QgZmlsZQo=");
                //printWriter.println("f9b4ef92212b8741:signed_sessionId:CHECKOUT:abb4ef42211b4720");
                //printWriter.println("f9b4ef92212b8740:signed_sessionId:DELETE:abb4ef42211b4720");
                //using OWNER delegation priv to add more delegation
                //printWriter.println("f9b4ef92212b8741:signed_sessionId:DELEGATE:abb4ef42211b4720:f9b4ef92212b8742:CHECKIN:600");
                //printWriter.println("f9b4ef92212b8740:signed_sessionId:DELEGATE:abb4ef42211b4720:f9b4ef92212b8741:BOTH:600");
                //delegate OWNER permission
                //printWriter.println("f9b4ef92212b8740:signed_sessionId:DELEGATE:abb4ef42211b4720:f9b4ef92212b8741:OWNER:600");
                //delegate checking
                //printWriter.println("f9b4ef92212b8740:signed_sessionId:DELEGATE:abb4ef42211b4720:f9b4ef92212b8743:CHECKIN:600");
                 * 
*/
                printWriter.println();
                printWriter.flush();

                String line = null;
                while ((line = bufferedReader.readLine()) != null) {
                    System.out.println("Inut : " + line);
                    String[] result = new String[2];
                    String status = "";
                    String docString = "N/A";
                    result = line.split(":");
                    status = result[0];
                    if (result.length > 1) {
                        docString = result[1];
                    }

                    //if (line.trim().equals("OK")) {
                    //if (status.equalsIgnoreCase("OK")) {
                        System.out.println("server sent: " + status);
                        System.out.println("docString: " + docString);
                        break;
                    //}
                }

                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        
        public String signID(String SessionID) {
        	
        	try {
   		   
   		        
   		        KeyStore client = KeyStore.getInstance("JKS");
   		        client.load(new FileInputStream("C:\\Users\\Typhoidmary\\source\\Dev\\src\\dev\\user.jks"), "cs6238".toCharArray());
   		        
   		        Key key = client.getKey("cs6238", "cs6238".toCharArray());	
   		        
   			        	Certificate cert  = client.getCertificate("cs6238");
   			        	
   			        	PublicKey pub = cert.getPublicKey();
   			        	KeyPair kp = new KeyPair(pub, (PrivateKey) key);
   			        	String encodedKey = Base64.getEncoder().encodeToString(SessionID.getBytes());
   			
   			            byte[] data = encodedKey.getBytes("UTF8");
   			
   			            Signature sig = Signature.getInstance("SHA1WithRSA");
   			            
   			            sig.initSign(kp.getPrivate());
   			            
   			            sig.update(data);
   			            byte[] signatureBytes = sig.sign();
   			            
   			
   			         
   			            
/***************************************************************************
 * This is the code to verify the signature
 */
   			            sig.initVerify(cert);
   			            sig.update(data);
   			
   			            System.out.println(sig.verify(signatureBytes));

   			        return Base64.getEncoder().encodeToString(signatureBytes);
   			            	
   			            
/*********   			          
 * End sig verification code
 */
   		        }catch (Exception ex) {
   		        	
   		        	System.out.println("Something went bang: " + ex.getMessage());
   		        	return null;
   		        }
        }
    }
}
