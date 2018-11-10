// SENG2250 System and Network Security
// School of Electrical Engineering and Computing
// Semester 2, 2018
// Assignment 3 
// Binbin Wang
// c3214157
import java.security.*;
import java.math.*;
import java.util.Base64;
import java.util.*;


public class C3214157A3{
	
	
	public static void main(String[] args) {
		User alice=new User("Alice");
		User bob=new User("Bob");
		System.out.println("==========================");

		System.out.println("==Alice and Bob uses STS protocol to establish a session key ==");
		System.out.println("==Once session key is created, they use 3-DES encryption to protect message confidentiality ==");
		System.out.println("==To enhance the security, they also apply the Counter Mode with 3-DES encryption for each message. ==");

		System.out.println("==========================");
		System.out.println("====Start simulation====");
		
		System.out.println("make two users Alice and Bob");

		//make the keys for each user
		alice.makeKeys(1024);
		System.out.println(alice.getName()+" make the keys");
		bob.makeKeys(1024);
		System.out.println(bob.getName()+" make the keys");
		
		// set public key and other user's [g^x]
		alice.setGYNum(bob.getGX());
		alice.setOtherPublicRSA(bob.getRSAPublicKey());
		System.out.println(alice.getName()+" get the bob's public key and g^x(bob)");
		
		bob.setGYNum(alice.getGX());
		bob.setOtherPublicRSA(alice.getRSAPublicKey());
		System.out.println(bob.getName()+" get the Alice's public key and g^x(alice)");	

		//alice and bob create them own g^y||g^x
		System.out.println("alice and bob create them own g^y||g^x");
		BigInteger aliceBI=new BigInteger(bob.getGX().toString()+alice.getGX().toString());
		BigInteger bobBI=new BigInteger(alice.getGX().toString()+bob.getGX().toString());


		//alice verify the share security Key
		if (alice.verify(bob.signature(bobBI))){
			System.out.println("alice confirms the share security Key and save it");
			
			//set the ShareSecretKey 
			alice.setShareSecretKey(bob.getDHPublicKey());
			alice.newNonce();
		}else{
			System.out.println("alice Denies the share security Key");
		}
		
		//bob verify the share security Key 
		if (bob.verify(alice.signature(aliceBI))){
			System.out.println("bob confirms the share security Key and save it");
			
			//set the ShareSecretKey 
			bob.setShareSecretKey(alice.getDHPublicKey());
			bob.newNonce();
		}else{
			System.out.println("bob Denies the share security Key");
		}

		
		
		// alice Encrypts a massage
		byte[] aliceEncryptM = alice.encryptMessage(//"hello bob"
													"12345678"+    //1
													"12345678"+    //2
													"12345678"+    //3
													"12345678"+    //4
													"12345678"+    //5
													"12345678"+    //6
													"12345678"+    //7
													"12345678");   //8

		//sand to bob

		System.out.println("alice's Encrypt Message:"+ Base64.getEncoder().encodeToString(aliceEncryptM) );		

		//bob Decrypts this massage
		byte[] bobDecryptM = bob.decryptMessage(aliceEncryptM);
		System.out.println("bob Decrypts this massage.");
		String dMessage1=new String(bobDecryptM);
		System.out.println("the message is:"+ dMessage1 );

		// bob Encrypts a massage
		byte[] bobEncryptM = bob.encryptMessage(//"hello alice"
													"87654321"+    //1
													"87654321"+    //2
													"87654321"+    //3
													"87654321"+    //4
													"87654321"+    //5
													"87654321"+    //6
													"87654321"+    //7
													"87654321");   //8

		//sand to bob
		System.out.println("alice's Encrypt Message:"+ Base64.getEncoder().encodeToString(bobEncryptM) );		

		//bob Decrypts this massage
		byte[] aliceDecryptM = bob.decryptMessage(bobEncryptM);
		System.out.println("bob Decrypts this massage.");
		String dMessage2=new String(aliceDecryptM);
		System.out.println("the message is:"+ dMessage2 );		

		System.out.println("==========================");

	}
		
}