// SENG2250 System and Network Security
// School of Electrical Engineering and Computing
// Semester 2, 2018
// Assignment 3 
// Binbin Wang
// c3214157
import java.security.*;
import java.math.*;
import java.util.*;


public class C3214157A3{
	
	
	public static void main(String[] args) {
		User alice=new User("Alice");
		User bob=new User("Bob");
		
		
		System.out.println("==========================");
		//make the keys for each user
		alice.makeKeys(1024);
		bob.makeKeys(1024);
		// set public key and other user's [g^x]
		alice.setGYNum(bob.getGX());
		alice.setOtherPublicRSA(bob.getRSAPublicKey());
		bob.setGYNum(alice.getGX());
		bob.setOtherPublicRSA(alice.getRSAPublicKey());
		
		BigInteger aliceBI=new BigInteger(bob.getGX().toString()+alice.getGX().toString());
		BigInteger bobBI=new BigInteger(alice.getGX().toString()+bob.getGX().toString());


		
		if (alice.verify(bob.signature(bobBI))){
			System.out.println("alice get the share security Key");
		}else{
			System.out.println("alice notget the share security Key");
		}

		if (bob.verify(alice.signature(aliceBI))){
			System.out.println("bob get the share security Key");
		}else{
			System.out.println("bob not get the share security Key");
		}

		
		//set the ShareSecretKey 
		alice.setShareSecretKey(bob.getDHPublicKey());
		bob.setShareSecretKey(alice.getDHPublicKey());
		//System.out.println("sssssss:"+alice.getsKey().toString());
		//System.out.println("sssssss:"+bob.getsKey().toString());
		byte[] aliceEncryptM = alice.encryptMessage(//"hello bob"
													"12345678"+    //1
													"12345678"+    //2
													"12345678"+    //3
													"12345678"+    //4
													"12345678"+    //5
													"12345678"+    //6
													"12345678"+    //7
													"12345678"     //8
													
													);//8*7=64
		
		String eMessage=new String(aliceEncryptM);
		//System.out.println("aliceEncryptM:"+ eMessage );		
		//System.out.println("aliceEncryptM:"+ aliceEncryptM.length );		
		//System.out.println("aliceEncryptM:"+ Base64.getEncoder().encodeToString(aliceEncryptM) );			
		
		byte[] bobDecryptM = bob.decryptMessage(aliceEncryptM);
		String message=new String(bobDecryptM);
		System.out.println("the message:"+ message );

		
		System.out.println("==========================");
		System.out.println("==STS==");
		System.out.println("==Alice and Bob uses STS protocol to establish a session key ==");
		//g of x 
		//AliceKeyPair 
		//BobKeyPair 
		
		//BigInteger genNum= BigInteger.probablePrime(1024,new Random());
		//BigInteger bigPrime= BigInteger.probablePrime(1024,new Random());
		
		System.out.println("==Once session key is created, they use 3-DES encryption to protect message confidentiality ==");
		System.out.println("==To enhance the security, they also apply the Counter Mode with 3-DES encryption for each message. ==");

		System.out.println("==========================");
		
		//System.out.println("==g=="+genNum);
		//System.out.println("=b======"+bigPrime);

	}
		
}