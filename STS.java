import java.security.*;
import java.math.*;
import java.util.*;

public class ProtocolSTS{

	//signature
    public static byte[] signatureRSA(byte[] data, String privateKey) throws Exception {

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // 取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(privateKey);
        // 用私钥对信息生成数字签名
        Signature signature = Signature.getInstance("SHA-256");
        signature.initSign(priKey);
        signature.update(data);
        return signature.sign();
    }
 
	// verify
    public static boolean verifyRSA(byte[] data, String publicKey, String sign) throws Exception {

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // 取公钥匙对象
        PublicKey pubKey = keyFactory.generatePublic(publicKey);
        Signature signature = Signature.getInstance("SHA-256");
        signature.initVerify(pubKey);
        signature.update(data);
        // 验证签名是否正常
        return signature.verify(sign);
    }	
	
	
	//////////////
	//////////////
	//////////////
	// SHA256
	private String SHA256(final String strText)
	{

		
		String strResult = null;
	 
		// 是否是有效字符串
		if (strText != null && strText.length() > 0){
			try{
				// SHA 加密开始
				// 创建加密对象 并傳入加密類型
				MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
				// 传入要加密的字符串
				messageDigest.update(strText.getBytes());
				// 得到 byte 類型结果
				byte byteBuffer[] = messageDigest.digest();
		 
				// 將 byte 轉換爲 string
				StringBuffer strHexString = new StringBuffer();
				// 遍歷 byte buffer
				for (int i = 0; i < byteBuffer.length; i++){
					String hex = Integer.toHexString(0xff & byteBuffer[i]);
					if (hex.length() == 1){
						strHexString.append('0');
					}
					strHexString.append(hex);
				}
				// 得到返回結果
				strResult = strHexString.toString();
				
			}catch (NoSuchAlgorithmException e){
				e.printStackTrace();
			}
		}
		return strResult;
	}
	
	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////
	

	
	public void run(int size){
		
		//size=1024
		
		// akey=generateRSAKeyPair
		// bkey=generateRSAKeyPair	
		KeyPair aliceKeyPair = generateKeyPair(size,"RSA");
		KeyPair bobKeyPair = generateKeyPair(size,"RSA");
		
		//DES
		KeyPair ssKeyG = generateKeyPair(size,"DH");
		KeyPair ssKeyAg= KeyAgreement.getInstance("DH");
		
		// a make skey(K)
		// b make skey(K)
		
		BigInteger genNum= BigInteger.probablePrime(size,new Random());
		BigInteger bigPrimeNum= BigInteger.probablePrime(size,new Random());
		
		//shareSecretKey=
		
		// g=bingintget. probablePrime()
		
		// g^r(Ax) send to bob
		// g^r(Bx) send to Alie
		
		// Alice: g^r(Ax) || g^r(Bx)
		// bob:  g^r(Bx) || g^r(Ax)
		
		// Signature "SHA256withRSA" use privet key and [||]
		//signature.getInstance("SHA256withRSA");
		//Signature signature = Signature.getInstance("SHA256withRSA");
		// sign and verify
		
		///end of sts
		
		
	}
	
	
	
	
	

	
/*

     // Encryption
    public static byte[] RSAEncryption(PublicKey key, byte[] plainText) {

        try {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    // Decrypt

    public static String RSADecrypt(PrivateKey key, byte[] encodedText) {

        try {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(encodedText));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }	

	
*/
	

	
	
	

}
	