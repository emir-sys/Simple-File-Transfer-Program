import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.*;
import java.util.zip.Inflater;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Server {
	
	private static PrivateKey serverDHPrivateKey;
	private static PublicKey serverDHPublicKey;

	public static void main(String[] args) throws Exception{
		
		PublicKey clientDHPublicKey = null;
		PublicKey clientRSAPublicKey = null;
		String DiffieHellman = "DH", RSA = "RSA", path;
		
		generateDHKeys();
		
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Waiting for client on port " + serverSocket.getLocalPort() + "...");
        Socket server = serverSocket.accept();
        
		DataOutputStream out = new DataOutputStream(server.getOutputStream());
		DataInputStream in = new DataInputStream(server.getInputStream());
		
		path = "server_" + in.readUTF();
		
		System.out.println("Path: " + path);
		
		clientDHPublicKey = receiveKey(in,DiffieHellman);
		clientRSAPublicKey = receiveKey(in,RSA);
		
		sendKey(getServerDHPublicKey(),out);
		
		SecretKeySpec sharedKeySpec = generateAESKey(clientDHPublicKey);
		
        
        byte[] iv = new byte[128/8];
        in.read(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
		int originalDataSize = in.readInt();
		int signatureSize = in.readInt();
		int encryptedSize = in.readInt();
		
		byte[] encryptedFile = new byte[encryptedSize];
		byte[] signature = new byte[signatureSize];
		byte[] originalData = new byte[originalDataSize];
		
		int totalBytesRead = 0;
		while (totalBytesRead < encryptedSize) {
		    int bytesRead = in.read(encryptedFile, totalBytesRead, encryptedSize - totalBytesRead);
		    if (bytesRead == -1) {
		        // End of stream reached
		        break;
		    }
		    totalBytesRead += bytesRead;
		}
		
		byte [] decryptedFile = decryptAES(encryptedFile, sharedKeySpec, ivspec);
		byte [] decompressedFile = decompressByteArray(decryptedFile);
		
		int numPaddingBytes = decompressedFile[decompressedFile.length - 1];
		
		byte[] unpaddedData = Arrays.copyOfRange(decompressedFile, 0, decompressedFile.length - numPaddingBytes);
		
		originalData = Arrays.copyOfRange(unpaddedData, 0, originalDataSize);
		signature = Arrays.copyOfRange(unpaddedData, originalDataSize, originalDataSize + signatureSize);
		
		/*int copyLength;
		if (originalDataSize > unpaddedData.length) {
		    copyLength = unpaddedData.length;
		} else {
		    copyLength = originalDataSize;
		}
		System.arraycopy(unpaddedData, 0, originalData, 0, copyLength);

		if (signatureSize > unpaddedData.length - copyLength) {
		    copyLength = unpaddedData.length - copyLength;
		} else {
		    copyLength = signatureSize;
		}
		System.arraycopy(unpaddedData, originalDataSize, signature, 0, copyLength);*/
		
		if (verifySignature(originalData,signature,clientRSAPublicKey)) {
			System.out.println("Message is verified. File is saved by server.");
			writeFile(path,originalData);
		}
		else {
			System.out.println("Message is not verified.");
		}
        
        serverSocket.close();
	}
	
	private static void generateDHKeys(){
		try {
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance("DH");
			kpgen.initialize(1024);
			KeyPair pair = kpgen.generateKeyPair();
			serverDHPublicKey = pair.getPublic();
			serverDHPrivateKey= pair.getPrivate();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void sendKey(PublicKey key, DataOutputStream out) {
		try {
			Encoder encoder = Base64.getEncoder();
			String encodedKey = encoder.encodeToString(key.getEncoded());
			out.writeUTF(encodedKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static PublicKey receiveKey(DataInputStream in, String algorithm) {
		String keyString;
		PublicKey key = null;
		Decoder decoder = Base64.getDecoder();
		try {
			keyString = in.readUTF();
			byte[] keyArray = decoder.decode(keyString);
			key = KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(keyArray));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return key;
	}
	
    
    private static byte[] decompressByteArray(byte [] array) throws Exception{
        Inflater decompressor = new Inflater();
        decompressor.setInput(array);
        ByteArrayOutputStream bos = new ByteArrayOutputStream(array.length);
        byte[] buf = new byte[1024];
        while (!decompressor.finished()) {
          int count = decompressor.inflate(buf);
          bos.write(buf, 0, count);

        }
        bos.close();
        byte[] decompressedData = bos.toByteArray();
        
        decompressor.end();
        
        return decompressedData;

    }
    
    
    /*private static byte[] decryptAES(byte[] file, SecretKeySpec key, IvParameterSpec iv) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		
		byte[] encryptedFile = cipher.doFinal(file);
    	
		return encryptedFile;
    }*/
    
    private static byte[] decryptAES(byte[] file, SecretKeySpec key, IvParameterSpec iv) throws Exception {
 		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
 		cipher.init(Cipher.DECRYPT_MODE, key, iv);
 		
 		int blockSize = 1024;
 	    int index = 0;
 	    byte[] encryptedData = new byte[0];
 	    while (index < file.length) {
 	      int length = Math.min(blockSize, file.length - index);
 	      byte[] block = Arrays.copyOfRange(file, index, index + length);
 	      index += length;
 	      encryptedData = concatenateArrays(encryptedData, cipher.update(block));
 	    }
 	    encryptedData = concatenateArrays(encryptedData, cipher.doFinal());
     	
 		return encryptedData;
 		
     }
    
    
    private static SecretKeySpec generateAESKey(PublicKey clientDHPublicKey) throws Exception{
    	KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(getServerDHPrivateKey());
        keyAgreement.doPhase(clientDHPublicKey, true);
        
        byte[] sharedSecretKeyArray = keyAgreement.generateSecret();
        byte[] shortenedKeyArray = new byte[32];
        System.arraycopy(sharedSecretKeyArray, 0, shortenedKeyArray, 0, 32);
        
        //SecretKeySpec sharedKeySpec = new SecretKeySpec(shortenedKeyArray, "AES");
        SecretKeySpec sharedKeySpec = new SecretKeySpec(sharedSecretKeyArray, 0, 32, "AES");
        
        return sharedKeySpec;
    }
    
    private static boolean verifySignature(byte[] originalData, byte[] signature, PublicKey clientRSAPublicKey) throws Exception {
		Signature sign = Signature.getInstance("SHA1withRSA");
		sign.initVerify(clientRSAPublicKey);
		sign.update(originalData);
		if(sign.verify(signature)){
			return true;
		}
		else {
			return false;
		}
    }
    
    private static void writeFile(String path, byte [] data) throws IOException {

        try(FileOutputStream fileOutputStream = new FileOutputStream(path)) {
            fileOutputStream.write(data);
        }

    }
    
    private static byte[] concatenateArrays(byte[] array1, byte[] array2) throws Exception{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(array1);
		outputStream.write(array2);
		byte concatenatedFile[] = outputStream.toByteArray();
		
    	return concatenatedFile;
    }
    

	private static PrivateKey getServerDHPrivateKey() {
		return serverDHPrivateKey;
	}

	private static PublicKey getServerDHPublicKey() {
		return serverDHPublicKey;
	}

}
