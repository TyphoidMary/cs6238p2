/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author jdw6
 */
//public class HTTPSServer {   
//}
//
//basic server/client code from https://www.pixelstech.net/article/1445603357-A-HTTPS-client-and-HTTPS-server-demo-in-Java
//import com.sun.xml.internal.ws.util.StringUtils;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

public class HTTPSServer {

    private int port = 9999;
    private boolean isServerDone = false;

    private static final String DOCSTORE = "documentStore/";
    private static final String META = "-meta";
    private static final String DEL = "-del";

    public static void main(String[] args) {
        HTTPSServer server = new HTTPSServer();
        server.run();
    }

    HTTPSServer() {
    }

    HTTPSServer(int port) {
        this.port = port;
    }

    // Create the and initialize the SSLContext
    private SSLContext createSSLContext() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("keystore.jks"), "cs6238".toCharArray());

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
            // Create server socket factory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create server socket
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);

            System.out.println("SSL server started");
            while (!isServerDone) {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

                // Start the server thread
                new ServerThread(sslSocket).start();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // Thread handling the socket from client
    static class ServerThread extends Thread {

        private SSLSocket sslSocket = null;

        ServerThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        public void run() {
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                // Start handshake
                //require client cert
                sslSocket.setNeedClientAuth(true);
                sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                System.out.println("SSLSession :");
                System.out.println("\tProtocol : " + sslSession.getProtocol());
                System.out.println("\tCipher suite : " + sslSession.getCipherSuite());
                //get ssl sesison id
                String sslSessionId = DatatypeConverter.printHexBinary(sslSession.getId());
                System.out.println("session ID: " + sslSessionId);

                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

                String line = null;
                String commandStatus = "";
                while ((line = bufferedReader.readLine()) != null) {
                    if (line.trim().isEmpty()) {
                        break;
                    }
                    System.out.println("Input recieved : " + line);
                    //do the client request
                    commandStatus = doCommand(sslSessionId, line);
                }

                // Write data
                //printWriter.print("HTTP/1.1 200\n");
                printWriter.print(commandStatus);
                printWriter.flush();

                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            System.out.println("-------Session Ended---------------");
        }
    }

    public static String doCommand(String sessionId, String input) {
        //parse the command sent by the client
        String status = "ERROR";
        int numVars = (int) input.chars().filter(ch -> ch == ':').count();
        //System.out.println("Recieved string vars: " + numVars);
        String[] inputSplit = new String[numVars];
        inputSplit = input.split(":");
        //System.out.println("string array: " + Arrays.toString(inputSplit));
        //make sure client sent enough vars
        if (inputSplit.length < 4) {
            System.out.println("Client send bad input");
            return "ERROR";
        }

        //teting
        //if (true) {
        //    return "OK";
        //}
        //first check that user is valid
        if (userLogin(sessionId, inputSplit[0], inputSplit[1])) {
            //user is valid
        } else {
            //user invalid
            return "ERROR";
        }

        //do the command
        switch (inputSplit[2]) {
            case "CHECKIN":
                System.out.println("Running checkin");
                status = checkin(inputSplit);
                break;
            case "CHECKOUT":
                System.out.println("Running checkout");
                status = checkout(inputSplit);
                break;
            case "DELEGATE":
                System.out.println("Running delegate");
                status = delegate(inputSplit);
                break;
            case "DELETE":
                System.out.println("Running delete");
                status = delete(inputSplit);
                break;
            default:
                System.out.println("Client send bad command");
                return "ERROR";
        }
        return status;
    }

    public static boolean userLogin(String sessionId, String UID, String signature) {
        //do Patrick's sig check
        return true;
    }

    public static String checkin(String[] inputArray) {
        //checkin a file
        String userId = inputArray[0];
        String command = inputArray[2];
        String securityFlag = inputArray[3];
        String docId = inputArray[4];
        String docString = inputArray[5];
        String sigString = "";
        //default owner_id is the userId
        String ownerId = userId;
        String fileString = docString;
        String fileMetaString = "";
        System.out.println("got DID: " + docId + " securityFlag: " + securityFlag + " and fileencoding: " + fileString);

        //create the docstore dir if it doesn't exist
        File directory = new File(DOCSTORE);
        if (!directory.exists()) {
            directory.mkdir();
        }

        try {
            //check for existing file
            if (docExists(docId)) {
                System.out.println("file " + docId + " already exists");
                //if file exists check that the user has permission
                if (!(checkPermission(userId, docId, command))) {
                    //fail if the user did not have permission to checkin existing doc
                    System.out.println("user " + userId + " did not have permission to " + command + " file " + docId);
                    return "ERROR";
                }
                //get current file owner
                ownerId = getOwnerId(docId);
            }

            //get a new random aes key use the current sessionId as a seed
            String aesKey = getAesKey();

            //do security action before writting file
            if (securityFlag.equalsIgnoreCase("CONFIDENTIALITY")) {
                //encrypt the doc
                System.out.println("Set to confidential document will be encrypted");
                fileString = aesEncryptDoc(aesKey, fileString);
            } else if (securityFlag.equalsIgnoreCase("INTEGRITY")) {
                //sign the file
                System.out.println("Set to integrity document will be signed");
                sigString = signDoc(aesKey, fileString);
            } else {
                System.out.println("Set to none document will be written as plain text");
            }
            //write file
            System.out.println("Writing file DID: " + docId);
            File file = new File(DOCSTORE + docId);
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(fileString);
            fileWriter.flush();
            fileWriter.close();

            //build the metadata
            System.out.println("Writing file meta-data DID: " + docId);
            //only store the key in encrypted form
            String aesKeyEncrypted = encryptWithServerPubKey(aesKey);
            fileMetaString = fileMetaString + "OWNER_ID=" + ownerId;
            fileMetaString = fileMetaString + "\nSECURITY=" + securityFlag;
            fileMetaString = fileMetaString + "\nAES_KEY=" + aesKeyEncrypted;
            fileMetaString = fileMetaString + "\nAES_SIG=" + sigString;
            //write the metadata to meta file
            File fileMeta = new File(DOCSTORE + docId + META);
            FileWriter fileWriterMeta = new FileWriter(fileMeta);
            fileWriterMeta.write(fileMetaString);
            fileWriterMeta.flush();
            fileWriterMeta.close();

            //writing file and metadata worked return OK
            return "OK";
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "ERROR";
    }

    public static boolean docExists(String docId) {
        //check if a file currently exists
        File checkFile = new File(DOCSTORE, docId);
        if (checkFile.exists()) {
            System.out.println("doc: " + docId + " exists");
            return true;
        }
        System.out.println("doc: " + docId + " does not exist");
        return false;
    }

    public static boolean delExists(String docId) {
        //check if a file currently exists
        File checkFile = new File(DOCSTORE, docId + DEL);
        if (checkFile.exists()) {
            System.out.println("doc: " + docId + " delegatin file exists");
            return true;
        }
        System.out.println("doc: " + docId + " delegation file does not exist");
        return false;
    }

    public static boolean checkPermission(String UID, String docId, String command) {
        //check if the file is owned by the user
        try {
            //read metadata file
            Properties docPropsM = new Properties();
            FileInputStream metaInM = new FileInputStream(DOCSTORE + docId + META);
            docPropsM.load(metaInM);
            metaInM.close();
            System.out.println("owner from metadata: " + docPropsM.getProperty("OWNER_ID"));
            if (UID.equalsIgnoreCase(docPropsM.getProperty("OWNER_ID"))) {
                //user owns the file no need to check further
                System.out.println("User " + UID + " owns the file");
                return true;
            }
        } catch (Exception e) {
            System.out.println("doc: " + docId + " error opening meta" + e);
        }

        //check for a delegation file
        if (!(delExists(docId))) {
            //no delegations file
            return false;
        } else {
            //remove exipred delegations
            cleanDelegations(docId);
        }
        try {
            //read delegation data file
            Properties docProps = new Properties();
            FileInputStream metaIn = new FileInputStream(DOCSTORE + docId + DEL);
            docProps.load(metaIn);
            metaIn.close();

            //first check for ALL delegation
            //check for delegation of ALL_comamndType (possible commandsTypes are: CHECKOUT, CHECKIN, OWNER)
            String delTimeCommand = docProps.getProperty("ALL_DEL_" + command);
            if (delTimeCommand != null) {
                if (delegationTime(delTimeCommand)) {
                    //command is within delegation time allow it
                    return true;
                }
            }
            System.out.println("test1");
            //check of delegatin of BOTH to ALL
            String delTimeBoth = docProps.getProperty("ALL_DEL_BOTH");
            if (delTimeBoth != null) {
                if (delegationTime(delTimeBoth)) {
                    //command is within delegation time allow it
                    return true;
                }
            }
            System.out.println("test2");

            //second check for User specific delegation
            //check for delegation time of user_comamndType
            String delTimeCommandUser = docProps.getProperty(UID + "_DEL_" + command);
            if (delTimeCommandUser != null) {
                System.out.println("deltime: " + delTimeCommandUser);
                if (delegationTime(delTimeCommandUser)) {
                    //command is within delegation time allow it
                    return true;
                }
            }
            System.out.println("test3");
            //check of delegation of BOTH to User
            String delTimeBothUser = docProps.getProperty(UID + "_DEL_BOTH");
            if (delTimeBothUser != null) {
                if (delegationTime(delTimeBothUser)) {
                    //command is within delegation time allow it
                    return true;
                }
            }

            System.out.println("test4");

        } catch (Exception e) {
            e.printStackTrace();
        }
        //the user is not the file owner and does not have the correct delegation
        //within the delegation time window, return false
        return false;
    }

    public static String getOwnerId(String docId) {
        try {
            Properties docProps = new Properties();
            FileInputStream metaIn = new FileInputStream(DOCSTORE + docId + META);
            docProps.load(metaIn);
            metaIn.close();

            //get the current owner ID
            return docProps.getProperty("OWNER_ID");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "ERROR";
    }

    public static String getAesKey() {
        //generate a new random aes key
        String newKey = "";
        //generate a new random to use as aesKey seed
        Random r = new Random();
        //pick random BigInt
        BigInteger rBI = new BigInteger(128, r);
        String keyString = rBI.toString();
        try {
            //Use md5 hash to turn key into 128 bits
            byte[] keyBytes = keyString.getBytes();
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] aesKeyBytes = md.digest(keyBytes);
            //convert to String
            newKey = DatatypeConverter.printHexBinary(aesKeyBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return newKey;
    }

    public static String encryptWithServerPubKey(String input) {
        //encrypt the document's AES key with the server's public key
        //return base64 encoded string
        return input;
    }

    public static String decryptWithServerPrivateKey(String input) {
        //decrypt the AES key stored as encrypted with the server's private key
        //recieved as base64 encoded string
        return input;
    }

    public static String checkout(String[] inputArray) {
        //checkout a file
        String userId = inputArray[0];
        String docId = inputArray[3];
        String docString = "";

        //check to see if document exists
        if (!(docExists(docId))) {
            //if the doc does not exist return error
            return "ERROR";
        }
        //check meta data for checkout permission
        if (!(checkPermission(userId, docId, "CHECKOUT"))) {
            System.out.println("User does not have permission to checkout doc");
            return "ERROR";
        }
        System.out.println("User has permission to checkout doc");

        //user has permission to checkout the doc
        try {
            //read metadata file
            Properties docProps = new Properties();
            FileInputStream metaIn = new FileInputStream(DOCSTORE + docId + META);
            docProps.load(metaIn);
            metaIn.close();

            //read the doc into a string
            try {
                File docF = new File(DOCSTORE + docId);
                Scanner input = new Scanner(docF);
                docString = input.nextLine();
            } catch (Exception e) {
                System.out.println("--ERROR reading doc file" + e);
            }

            //check document security
            String securityFlag = docProps.getProperty("SECURITY");
            if (securityFlag.equalsIgnoreCase("CONFIDENTIALITY")) {
                //decrypt file
                docString = decryptDoc(docProps.getProperty("AES_KEY"), docString);
            } else if (securityFlag.equalsIgnoreCase("INTEGRITY")) {
                //unsign file ?
                if (!(checkDocSign(docProps.getProperty("AES_KEY"), docProps.getProperty("AES_SIG"), docString))) {
                    //signature does not match actual doc, return error
                    return "ERROR";
                }
            } else {
                //no security just send file
            }
            //return the doc
            return "OK:" + docString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        //return error by default
        return "ERROR";
    }

    public static String delegate(String[] inputArray) {
        //delegate a file
        String userId = inputArray[0];
        String docId = inputArray[3];
        String delUser = inputArray[4];
        String delPerm = inputArray[5];
        String delTime = inputArray[6];

        //check to see if document exists
        if (!(docExists(docId))) {
            //if the doc does not exist return error
            return "ERROR";
        }

        //check for permissions
        if (userId.equalsIgnoreCase(getOwnerId(docId))) {
            System.out.println("User " + userId + " is doc owner allow delagate request for doc: " + docId);
        } else {
            //user is not doc owner check for owner delegation

            if (checkPermission(userId, docId, "OWNER")) {
                //user has valid owner permission
                System.out.println("User " + userId + " has valid doc owner delegation allow delagate request for doc: " + docId);
            } else {
                //user does not have valid owner permissions to delegate doc
                System.out.println("User " + userId + " does not have doc owner delegation deny delagate request for doc: " + docId);
                return "ERROR";
            }
        }

        //don't allow a user to re-add self as an OWNER delegation
        if (delPerm.equalsIgnoreCase("OWNER") && delUser.equalsIgnoreCase(userId)) {
            System.out.println("User " + userId + " can not re-add self owner delegation deny delagate request for doc: " + docId);
            return "ERROR";
        }

        //verify valid delegation type
        if (delPerm.equalsIgnoreCase("CHECKOUT") || delPerm.equalsIgnoreCase("CHECKIN") || delPerm.equalsIgnoreCase("BOTH") || delPerm.equalsIgnoreCase("OWNER")) {
            String pumpkinTime = getFutureTime(delTime);
            String fileDelegation = "\n" + delUser + "_DEL_" + delPerm + "=" + pumpkinTime;

            try {
                //append the delegation to the metadata file
                File fileMeta = new File(DOCSTORE + docId + DEL);
                //open metaData file in append mode
                FileWriter fileWriterMeta = new FileWriter(fileMeta, true);
                fileWriterMeta.write(fileDelegation);
                fileWriterMeta.flush();
                fileWriterMeta.close();
                return "OK";
            } catch (Exception e) {
                System.out.println("--ERROR reading doc file" + e);
            }
        }

        //return error by default
        return "ERROR";
    }

    public static void cleanDelegations(String docId) {
        try {
            File inputF = new File(DOCSTORE + docId + DEL);
            Scanner input = new Scanner(inputF);
            String line = "";
            String metaString = "";
            String[] delString = new String[2];
            while (input.hasNext()) {
                line = input.nextLine();
                if (line.contains("_DEL_")) {
                    //check delegation time
                    delString = line.split("=");
                    if (delegationTime(delString[1])) {
                        //if the delegation time is till valid include it
                        metaString = metaString + line + "\n";
                    } else {
                        //remove expired delegation
                        System.out.println("Removing expored delegation: " + line);
                    }
                } else {
                    //keep all metadata lines that are not delegation lines
                    metaString = metaString + line + "\n";
                }
            }
            //remove training whitespace
            metaString = metaString.trim();
            //write updated metadata
            File fileMeta = new File(DOCSTORE + docId + DEL);
            //open metaData file in append mode
            FileWriter fileWriterMeta = new FileWriter(fileMeta);
            fileWriterMeta.write(metaString);
            fileWriterMeta.flush();
            fileWriterMeta.close();
        } catch (Exception e) {
            System.out.println("---ERROR reading input file---");
            e.printStackTrace();
        }
        return;
    }

    public static String getFutureTime(String timeSec) {
        //convert timeSec into an long
        long delTime = DatatypeConverter.parseLong(timeSec);
        //get current time and add the delegation time in seconds
        long currentTime = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()) + delTime;
        //return the future time as a string
        return DatatypeConverter.printLong(currentTime);
    }

    public static boolean delegationTime(String delTime) {
        //get the current time
        long currentTime = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
        //convert the passed into a long
        long delPumpkin = DatatypeConverter.parseLong(delTime);
        if (delPumpkin > currentTime) {
            //delegation is still valid
            System.out.println("Delegation time is valid");
            return true;
        }
        //delegation is expired
        System.out.println("Delegation time is expired");
        return false;
    }

    public static String delete(String[] inputArray) {
        //delete a file securely
        String userId = inputArray[0];
        String docId = inputArray[3];
        String docString = "";

        //check to see if document exists
        if (!(docExists(docId))) {
            //if the doc does not exist return error
            return "ERROR";
        }

        //check for permissions only the owner can delete a doc
        if (!(userId.equalsIgnoreCase(getOwnerId(docId)))) {
            //user is not owner deny delete request
            System.out.println("User " + userId + " is not doc owner deny delete request for doc: " + docId);
            return "ERROR";
        }

        try {
            //First read the doc into a string
            File docF = new File(DOCSTORE + docId);
            Scanner input = new Scanner(docF);
            docString = input.nextLine();
            //then encrypt the docString
            String aesKey = getAesKey();
            docString = aesEncryptDoc(aesKey, docString);
            //overwrite the doc file on disk with encrypted version before deleting
            FileWriter fileWriter = new FileWriter(docF);
            fileWriter.write(docString);
            fileWriter.flush();
            fileWriter.close();
            //then delete the file
            docF.delete();
            //also delete the metadata
            File docM = new File(DOCSTORE + docId + META);
            docM.delete();
            System.out.println("Deleted metadata and doc: " + docId);
            return "OK";
        } catch (Exception e) {
            System.out.println("--ERROR reading doc file" + e);
        }
        //something went wrong
        return "ERROR";
    }

    public static String aesEncryptDoc(String keyString, String data) {
        String cipherText = null;
        //use static IV
        String iV = "098ad9f9c34d8be56daf00380c0bd665";
        try {
            //Use md5 hash to turn key into 128 bits
            byte[] keyBytes = keyString.getBytes();
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] aesKeyBytes = md.digest(keyBytes);
            //used 128 hash of key to decrypt with aes
            Key key = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            IvParameterSpec ivSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(iV));
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            //c.init(Cipher.ENCRYPT_MODE, key);
            byte[] cypherBytes = c.doFinal(data.getBytes());
            cipherText = Base64.getEncoder().encodeToString(cypherBytes);
            System.out.println("Encrypted doc string");
        } catch (Exception e) {
            System.out.println("---ERROR when encrypting string---");
            System.out.println(e);
        }
        return cipherText;
    }

    public static String decryptDoc(String keyString, String cipherString) {
        //decrypt the string
        String plainText = "FAILED";
        String iV = "098ad9f9c34d8be56daf00380c0bd665";
        try {
            //Use md5 hash to turn key into 128 bits
            byte[] keyBytes = keyString.getBytes();
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] aesKeyBytes = md.digest(keyBytes);
            //used 128 hash of key to decrypt with aes
            Key key = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            IvParameterSpec ivSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(iV));
            c.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] cipherBytes = Base64.getDecoder().decode(cipherString);
            byte[] plainBytes = c.doFinal(cipherBytes);
            plainText = new String(plainBytes);
        } catch (Exception e) {
            System.out.println("---ERROR when decrypting string---");
            System.out.println(e);
        }
        return plainText;
    }

    public static String signDoc(String aesKey, String fileString) {
        //sign the doc string with somehow using the aesKey
        //base64 encode the string if it's not a one line plain text
        return "this_is_a_doc_signature";
    }

    public static boolean checkDocSign(String aesKey, String docSig, String docString) {
        //check the doc signature (was the sig base64 encoded?)
        return true;
    }
}
