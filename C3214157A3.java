// SENG2250 System and Network Security
// School of Electrical Engineering and Computing
// Semester 2, 2018
// Assignment 3 
// Binbin Wang
// c3214157
import java.security.*;
import java.math.*;
import java.util.Random;


public class C3214157A3{
	
	
	public static void main(String[] args) {
		User alice=new User("Alice");
		User bob=new User("Bob");
		
		
		System.out.println("==========================");
		// System.out.println("=b=="+bob.getX());
		// System.out.println("=bx=="+bob.getGX());
		// System.out.println("=a=="+alice.getX());
		// System.out.println("=ax=="+alice.getGX());
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