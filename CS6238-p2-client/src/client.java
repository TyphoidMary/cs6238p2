import javax.crypto.*;
import javax.net.*;
import javax.net.ssl.SSLContext;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.io.File;
import java.io.FileInputStream;
import com.chilkatsoft.*;



public class client {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}
	

	public static CkHttp connect() throws Exception {
		boolean sucess;
		try {
	        System.loadLibrary("chilkat");
	    } catch (UnsatisfiedLinkError e) {
	      System.err.println("Native code library failed to load.\n" + e);
	      System.exit(1);
	    }
		
		CkHttp http = new CkHttp();
		sucess = http.UnlockComponent("string");
		
		if(!sucess)	{			
			System.out.println(http.lastErrorText());
			throw new Exception("Something has gone horribly wrong with the Chilkat lib. Consider alcoholisim?");
		}
		
		sucess = http.SetSslClientCertPfx("/some/file/path/to/pfx/file", "changeit"); //args are path to pfx file and it's private key password
		
		if(!sucess) {
			System.out.println(http.lastErrorText());
			throw new Exception("Could not associate certificate and private key with HTTP commection");
		}
		
		 	http.put_AcceptCharset("");
		    http.put_UserAgent("");
		    http.put_AcceptLanguage("");
		    //  Suppress the Accept-Encoding header by disallowing a gzip response:
		    http.put_AllowGzip(false);
		    
		return http;
	      
	}
	
	public static Boolean authenticate(CkHttp http) throws Exception {
		 
		CkGlobal glob = new CkGlobal();
		    boolean success = glob.UnlockBundle("Anything for 30-day trial");
		    if (success != true) {
		        System.out.println(glob.lastErrorText());
		        return false;
		    }
		    
		    /*
		     * Generate ephemeral key material
		    */
		    
		    //  This will be our source of random data for generating the ECC private key.
		    CkPrng fortuna = new CkPrng();
		    String entropy = fortuna.getEntropy(32,"base64");
		    success = fortuna.AddEntropy(entropy,"base64");

		    CkEcc ecc = new CkEcc();

		    //  Generate a random ECC private key on the secp256r1 curve.
		    //  Chilkat also supports other curves, such as secp384r1, secp521r1, and secp256k1.

		    CkPrivateKey privKey = ecc.GenEccKey("secp256r1",fortuna);
		    if (privKey == null ) {
		        System.out.println(ecc.lastErrorText());
		        return false;
		        }

		   
		    CkHttpResponse response = http.PostJson("https://project.local/endpoint", privKey.getJwk());
		    
		    if(response == null) {
		    
		    	throw new Exception(http.lastErrorText());
		    }
		    
		    CkJsonObject responseBody = new CkJsonObject();
		    		responseBody.Load(response.bodyStr());
		    		
		    CkJsonObject peerKey = responseBody.FindObjectWithMember("PeerKey");
		    
		    if(peerKey == null)
		    {
		    	throw new Exception("PeerKey missing from peer HTTP response. Abort Abort Abort");
		    }
		    
		    /*
		     * Do something with the exchanged keys
		     */
		    
		    return true;
		    
		    
	}
	
	public static void putFile(File file, CkHttp http) {
		
		
	}
	
	public static File getFile(String fileName, CkHttp http) {
		
		return null;
		
	}

}
