import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.zip.Deflater;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Client {
	private static PublicKey clientDHPublicKey;
	private static PrivateKey clientDHPrivateKey;
	private static PublicKey clientRSAPublicKey;
	private static PrivateKey clientRSAPrivateKey;

	
	public static void main(String[] args) throws Exception{
		
		PublicKey serverDHPublicKey = null;
		String DiffieHellman = "DH";
		String path;
		
		generateDHKeys();
		generateRSAKeys();
		
		System.out.println("Connecting to localhost on port 8080");
		Socket client = new Socket("localhost", 8080);
		System.out.println("Connected to "+ client.getRemoteSocketAddress());
		
		DataOutputStream out = new DataOutputStream(client.getOutputStream());
		DataInputStream in = new DataInputStream(client.getInputStream());
		
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter filename: ");
		path = sc.nextLine();
		sc.close();
		
		out.writeUTF(path);
		
		sendKey(getClientDHPublicKey(),out);
		
		sendKey(getClientRSAPublicKey(),out);
		
		serverDHPublicKey = receiveKey(in,DiffieHellman);
		
		SecretKeySpec sharedKeySpec = generateAESKey(serverDHPublicKey);
        
	    byte[] iv = generateIV();
	    out.write(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
        
        byte [] fileData = fileToByteArray(path);
		out.writeInt(fileData.length);
		
		byte[] signature = generateSignature(fileData);
		out.writeInt(signature.length);
		
		byte[] concatenatedFile = concatenateArrays(fileData,signature);
		
		int concatenatedFileLength = concatenatedFile.length;
        int blockSize = 16;
        int numPaddingBytes = (int)Math.ceil((double)concatenatedFileLength / blockSize) * blockSize - concatenatedFileLength;
        
        byte[] paddedFileData = new byte[concatenatedFileLength + numPaddingBytes];
        System.arraycopy(concatenatedFile, 0, paddedFileData, 0, concatenatedFileLength);
        for (int i = concatenatedFileLength; i < paddedFileData.length; i++) {
            paddedFileData[i] = (byte)numPaddingBytes;
        }
		
		byte[] compressedFile = compressByteArray(concatenatedFile);
		
		byte[] encryptedFile = encryptAES(compressedFile,sharedKeySpec,ivspec);
		out.writeInt(encryptedFile.length);

		out.write(encryptedFile);
		
		
		/*System.out.println("Original data size: " + fileData.length);
		System.out.println("Signature size: " + signature.length);
		System.out.println("Concatenated size: " + concatenatedFile.length);
		System.out.println("Compressed size: " + compressedFile.length);
		System.out.println("Encrypted size: " + encryptedFile.length);*/
		
		
		/*System.out.println("Original byte array: " + Arrays.toString(fileData));
		System.out.println("Signature: " + Arrays.toString(signature));
		System.out.println("Concatenated byte array: " + Arrays.toString(concatenatedFile));
		System.out.println("Encrypted byte array: " + Arrays.toString(encryptedFile));
		System.out.println("Compressed byte array: " + Arrays.toString(compressedFile));*/
		
		
		
		client.close();
	}
	
	private static void generateDHKeys(){
		try {
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance("DH");
			kpgen.initialize(1024);
			KeyPair pair = kpgen.generateKeyPair();
			clientDHPublicKey = pair.getPublic();
			clientDHPrivateKey= pair.getPrivate();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void generateRSAKeys(){
		try {
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance("RSA");
			kpgen.initialize(1024);
			KeyPair pair = kpgen.generateKeyPair();
			clientRSAPublicKey = pair.getPublic();
			clientRSAPrivateKey= pair.getPrivate();
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
    
    
    private static byte[] compressByteArray(byte [] array) throws IOException {
		Deflater compressor = new Deflater();
		compressor.setLevel(Deflater.BEST_COMPRESSION);
		compressor.setInput(array);
		compressor.finish();

		ByteArrayOutputStream bos = new ByteArrayOutputStream(array.length);
		byte[] buf = new byte[1024];
		 
		while (!compressor.finished()) {
			 int count = compressor.deflate(buf);
		     bos.write(buf, 0, count);
		}
		 
		bos.close();
		
		byte[] compressedData = bos.toByteArray();
		
		return compressedData;
    }
    
    /*private static byte[] encryptAES(byte[] file, SecretKeySpec key, IvParameterSpec iv) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		
		byte[] encryptedFile = cipher.doFinal(file);
    	
		return encryptedFile;
    }*/
    
    private static byte[] encryptAES(byte[] file, SecretKeySpec key, IvParameterSpec iv) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		
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
    
    private static byte[] concatenateArrays(byte[] array1, byte[] array2) throws Exception{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(array1);
		outputStream.write(array2);
		byte concatenatedFile[] = outputStream.toByteArray();
		
    	return concatenatedFile;
    }
    
    private static byte[] fileToByteArray (String path) throws Exception {
	    File file = new File(path);
        byte [] fileData = new byte[(int) file.length()];

        try(FileInputStream fileInputStream = new FileInputStream(file)) {
            fileInputStream.read(fileData);
        }
        
        return fileData;
    	
    }
    
    private static byte[] generateIV() {
		SecureRandom srandom = new SecureRandom();
		byte[] iv = new byte[128/8];
		srandom.nextBytes(iv);
		
		return iv;
    }
    
    private static byte[] generateSignature(byte[] fileData) throws Exception {
		Signature sign = Signature.getInstance("SHA1withRSA");
		sign.initSign(getClientRSAPrivateKey());
		sign.update(fileData);
		byte[] signature = sign.sign();
		
		return signature;
    }
    
    private static SecretKeySpec generateAESKey(PublicKey serverDHPublicKey) throws Exception{
    	KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(getClientDHPrivateKey());
        keyAgreement.doPhase(serverDHPublicKey, true);
        
        byte[] sharedSecretKeyArray = keyAgreement.generateSecret();
        byte[] shortenedKeyArray = new byte[32];
        System.arraycopy(sharedSecretKeyArray, 0, shortenedKeyArray, 0, 32);
        
        //SecretKeySpec sharedKeySpec = new SecretKeySpec(shortenedKeyArray, "AES");
        SecretKeySpec sharedKeySpec = new SecretKeySpec(sharedSecretKeyArray, 0, 32, "AES");
        
        return sharedKeySpec;
    }
    
    
    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
    	    File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
    	    NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
    	    BadPaddingException, IllegalBlockSizeException {
    	    
    	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    	    FileInputStream inputStream = new FileInputStream(inputFile);
    	    FileOutputStream outputStream = new FileOutputStream(outputFile);
    	    byte[] buffer = new byte[64];
    	    int bytesRead;
    	    while ((bytesRead = inputStream.read(buffer)) != -1) {
    	        byte[] output = cipher.update(buffer, 0, bytesRead);
    	        if (output != null) {
    	            outputStream.write(output);
    	        }
    	    }
    	    byte[] outputBytes = cipher.doFinal();
    	    if (outputBytes != null) {
    	        outputStream.write(outputBytes);
    	    }
    	    inputStream.close();
    	    outputStream.close();
    	}
	
	private static PrivateKey getClientDHPrivateKey() {
		return clientDHPrivateKey;
	}

	private static PublicKey getClientDHPublicKey() {
		return clientDHPublicKey;
	}
	
	private static PrivateKey getClientRSAPrivateKey() {
		return clientRSAPrivateKey;
	}

	private static PublicKey getClientRSAPublicKey() {
		return clientRSAPublicKey;
	}
	
	

}
