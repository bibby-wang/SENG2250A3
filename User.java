
import java.security.*;
import java.math.*;
import java.util.*;
import javax.crypto.*;

public class User{
	String name;
	private KeyPair keyPairRSA;
	private KeyPair keyPairDH;
	private SecretKey shareSecretKey;
	private int privateNum;


	//private KeyPair ssKeyAg;
	
	private BigInteger generatorNum;

	private BigInteger numberGY;
	private BigInteger primeNum;
	
	public User(){
		generatorNum= BigInteger.probablePrime(1024,new SecureRandom());
		primeNum= BigInteger.probablePrime(1024,new SecureRandom());
		privateNum=new SecureRandom().nextInt(20)+2;
	}
	
	public User(String name){
		this();
		this.name=name;

	}
	// make the keys
	public void makeKeys(int size){
		keyPairRSA = generateKeyPair(size,"RSA");
		keyPairDH = generateKeyPair(size,"DH");
		//ssKeyAg= KeyAgreement.getInstance("DH");
	}
	
	// signature 
	public byte[] signature(BigInteger sessionKey){
		byte[] tempByte = null;
		try {
			PrivateKey privateRSA=keyPairRSA.getPrivate();
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(privateRSA,new SecureRandom());
			sign.update(sessionKey.toByteArray());
			tempByte = sign.sign();
		} catch (Exception e) {
			
		}
		return tempByte;
	}
	
	// verify
	public boolean verify(byte[] singData){
		boolean tempBoolean=false;
		try{
			PrivateKey privateRSA=keyPairRSA.getPrivate();
			Signature sing = Signature.getInstance("SHA256withRSA");
		
			//sing.updata(sessionKey.toByteArray());
			tempBoolean=sing.verify(singData);
		} catch (Exception e) {
			
		}
		return tempBoolean;
	}
	// set the ShareSecretKey by other user's public key
	public void setShareSecretKey(PublicKey publicKey){
		PrivateKey privateDH=keyPairDH.getPrivate();
		try {
			

			
			
		} catch (Exception e) {
			
		}
		
		//shareSecretKey=;
	}	
	
		
	
	// get generator number
	public void setGenNum(BigInteger gy){
		numberGY=gy;
	}
	
	// SecureRandom
	public int getX(){
		return privateNum;
		
	}	
	// get g^x number
	public BigInteger getGX(){
		return generatorNum.pow(privateNum);
		
	}
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
		

	
	//get the RSA key public and privet
	private static KeyPair generateKeyPair(int keyLength,String type)
	{
		try
		{
			KeyPairGenerator keyPair = KeyPairGenerator.getInstance(type);
			keyPair.initialize(keyLength);
			return keyPair.genKeyPair();
		} catch (Exception e){
			return null;
		}
	}

	
	
}