// SENG2250 System and Network Security
// School of Electrical Engineering and Computing
// Semester 2, 2018
// Assignment 3 Task 2
// Binbin Wang
// c3214157
import java.security.*;
import java.math.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class User{
	private String name;
	private KeyPair keyPairRSA;
	private KeyPair keyPairDH;
	private int privateNum;
	private BigInteger generatorNum;
	private BigInteger primeNum;
    // share 
	private SecretKey sharesecurityKey;	
	private IvParameterSpec ivPS;
	//from other user
	private PublicKey otherPublicRSA;
	private BigInteger numberGY;


	public User(){
		generatorNum= BigInteger.probablePrime(1024,new SecureRandom());
		primeNum= BigInteger.probablePrime(1024,new SecureRandom());
		privateNum=new SecureRandom().nextInt(20)+2;
	}
	
	public User(String name){
		this();
		this.name=name;

	}
	//get name
	public String getName(){return name;}
	
	// make the keys
	public void makeKeys(int size){
		keyPairRSA = generateKeyPair(size,"RSA");
		keyPairDH = generateKeyPair(size,"DH");
		
	}
	
	// signature 
	public byte[] signature(BigInteger id){
		byte[] tempByte = null;
		try {
			PrivateKey privateRSA=keyPairRSA.getPrivate();
			Signature digitalSignature = Signature.getInstance("SHA256withRSA");
			digitalSignature.initSign(privateRSA,new SecureRandom());
			digitalSignature.update(id.toByteArray());
			tempByte = digitalSignature.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return tempByte;
	}
	
	// verify
	public boolean verify(byte[] signData){
		boolean tempBoolean=false;
		try{
			//link two bigints
			BigInteger all=new BigInteger(this.getGX().toString()+ numberGY.toString());
			Signature digitalSignature = Signature.getInstance("SHA256withRSA");
			digitalSignature.initVerify(otherPublicRSA);
			digitalSignature.update(all.toByteArray());
			tempBoolean=digitalSignature.verify(signData);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return tempBoolean;
	}

		
	
	// set generator number from other user
	public void setGYNum(BigInteger gy){
		numberGY=gy;
	}
	// set PublicRSA key from other user
	public void setOtherPublicRSA(PublicKey publickey){
		otherPublicRSA=publickey;
	}
	

	// get g^x number
	public BigInteger getGX(){
		return generatorNum.pow(privateNum);
		
	}
	// get g
	public BigInteger getGenNum(){
		return generatorNum;
	}
	
	//get prime
	public BigInteger getPrimeNum(){
		return primeNum;
	}
	
	
	// get RSA Public Key
	public PublicKey getRSAPublicKey(){
		return keyPairRSA.getPublic();
	}
	

	//	get DH Public Key
	public PublicKey getDHPublicKey(){
		return keyPairDH.getPublic();
	}
	
	// set the ShareSecretKey by other user's public key
	public void setShareSecretKey(PublicKey publicKey){
		PrivateKey privateDH=keyPairDH.getPrivate();
		try {
			SecretKeyFactory secretKeyFactory= SecretKeyFactory.getInstance("DESede");
			KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
			keyAgreement.init(privateDH);
			keyAgreement.doPhase(publicKey,true);
			
			sharesecurityKey =secretKeyFactory.generateSecret(new DESedeKeySpec(keyAgreement.generateSecret()));
			//set a count number
			byte[] nonceByte={0x0c, 0x04, 0x01, 0x07, 0x09, 0x03, 0x02, 0x0c};
			ivPS = new IvParameterSpec(nonceByte);

			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}


     // Encrypt message
	public byte[] encryptMessage(String message){
		byte[] tempMesssage = message.getBytes();
		byte[] nonceCountByte=new byte[16];
		byte[] cipherByte=new byte[64];

		try{
			Cipher cipher = Cipher.getInstance("DESede/CTR/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, sharesecurityKey, ivPS);
			return cipher.doFinal(tempMesssage);
		}catch (Exception e) {
			e.printStackTrace();
		}
		
		return tempMesssage;
	}		

    // Decrypt message
	public byte[] decryptMessage(byte[] message){
		byte[] tempMesssage=message;

		try{
			Cipher cipher = Cipher.getInstance("DESede/CTR/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, sharesecurityKey, ivPS);
			tempMesssage=cipher.doFinal(message);
		}catch (Exception e) {
			e.printStackTrace();
		}

		return tempMesssage;
	}
	

	//get the "type" key public and privet
	private static KeyPair generateKeyPair(int keyLength,String type){
		try
		{
			KeyPairGenerator keyPair = KeyPairGenerator.getInstance(type);
			keyPair.initialize(keyLength);
			return keyPair.genKeyPair();
		} catch (Exception e){
			e.printStackTrace();
			return null;
		}
	}

	
	
}