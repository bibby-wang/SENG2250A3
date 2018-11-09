

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import com.jianggujin.codec.util.JCipherInputStream;
import com.jianggujin.codec.util.JCipherOutputStream;
import com.jianggujin.codec.util.JCodecException;

/**
 * Diffie-Hellman算法(D-H算法)，密钥一致协议。是由公开密钥密码体制的奠基人Diffie和Hellman所提出的一种思想。
 * 简单的说就是允许两名用户在公开媒体上交换信息以生成"一致"的、可以共享的密钥。换句话说，就是由甲方产出一对密钥（公钥、私钥），
 * 乙方依照甲方公钥产生乙方密钥对（公钥、私钥）。以此为基线，作为数据传输保密基础，同时双方使用同一种对称加密算法构建本地密钥（SecretKey）对数据加密
 * 。这样，在互通了本地密钥（SecretKey）算法后，甲乙双方公开自己的公钥，使用对方的公钥和刚才产生的私钥加密数据，
 * 同时可以使用对方的公钥和自己的私钥对数据解密。不单单是甲乙双方两方，可以扩展为多方共享数据通讯，这样就完成了网络交互数据的安全通讯！
 * 该算法源于中国的同余定理——中国馀数定理
 * <ol>
 * <li>甲方构建密钥对儿，将公钥公布给乙方，将私钥保留；双方约定数据加密算法；乙方通过甲方公钥构建密钥对儿，将公钥公布给甲方，将私钥保留。</li>
 * <li>甲方使用私钥、乙方公钥、约定数据加密算法构建本地密钥，然后通过本地密钥加密数据，发送给乙方加密后的数据；乙方使用私钥、甲方公钥、
 * 约定数据加密算法构建本地密钥，然后通过本地密钥对数据解密。</li>
 * <li>乙方使用私钥、甲方公钥、约定数据加密算法构建本地密钥，然后通过本地密钥加密数据，发送给甲方加密后的数据；甲方使用私钥、乙方公钥、
 * 约定数据加密算法构建本地密钥，然后通过本地密钥对数据解密。</li>
 * </ol>
 * 
 * @author jianggujin
 * 
 */
public class JDH {

   private final static String ALGORITHM = "DH";

   /**
    * 对称算法
    * 
    * @author jianggujin
    *
    */
   public static enum JDHSymmetricalAlgorithm {
      DES, DESede;
      public String getName() {
         return this.name();
      }
   }

   /**
    * 初始化甲方密钥
    * 
    * @return
    */
   public static KeyPair initPartyAKey() {
      return initPartyAKey(1024);
   }

   /**
    * 初始化甲方密钥
    * 
    * @param keySize
    * @return
    */
   public static KeyPair initPartyAKey(int keySize) {
      try {
         KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM);
         keyPairGen.initialize(keySize);
         return keyPairGen.generateKeyPair();
      } catch (NoSuchAlgorithmException e) {
         throw new JCodecException(e);
      }
   }

   /**
    * 初始化乙方密钥
    * 
    * @param partyAPublicKey
    *           甲方公钥
    * @return
    */
   public static KeyPair initPartyBKey(byte[] partyAPublicKey) {
      try {
         X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(partyAPublicKey);
         KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
         PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

         // 由甲方公钥构建乙方密钥
         DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();

         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
         keyPairGenerator.initialize(dhParamSpec);

         return keyPairGenerator.generateKeyPair();
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * 加密
    * 
    * @param data
    *           加密数据
    * @param privateKey
    *           己方私钥
    * @param publicKey
    *           对方公钥
    * @param algorithm
    *           对称算法
    * @return
    */
   public static byte[] encrypt(byte[] data, byte[] privateKey, byte[] publicKey, String algorithm) {
      // 数据加密
      Cipher cipher = getEncryptCipher(privateKey, publicKey, algorithm);

      try {
         return cipher.doFinal(data);
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * 包裹输出流，包裹后的输出流为加密输出流
    * 
    * @param out
    * @param privateKey
    * @param publicKey
    * @param algorithm
    * @return
    */
   public static OutputStream wrap(OutputStream out, byte[] privateKey, byte[] publicKey, String algorithm) {
      // 数据加密
      Cipher cipher = getEncryptCipher(privateKey, publicKey, algorithm);

      return new JCipherOutputStream(cipher, out);
   }

   /**
    * 获得加密模式的{@link Cipher}
    * 
    * @param privateKey
    * @param publicKey
    * @param algorithm
    * @return
    */
   public static Cipher getEncryptCipher(byte[] privateKey, byte[] publicKey, String algorithm) {
      return getCipher(privateKey, publicKey, algorithm, Cipher.ENCRYPT_MODE);
   }

   /**
    * 解密
    * 
    * @param data
    *           解密数据
    * @param privateKey
    *           己方私钥
    * @param publicKey
    *           对方公钥
    * @param algorithm
    *           对称算法
    * @return
    */
   public static byte[] decrypt(byte[] data, byte[] privateKey, byte[] publicKey, String algorithm) {
      // 数据解密
      Cipher cipher = getDecryptCipher(privateKey, publicKey, algorithm);
      try {
         return cipher.doFinal(data);
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * 包裹输入流，原输入流为加密数据输入流
    * 
    * @param in
    * @param privateKey
    * @param publicKey
    * @param algorithm
    * @return
    */
   public static InputStream wrap(InputStream in, byte[] privateKey, byte[] publicKey, String algorithm) {
      // 数据解密
      Cipher cipher = getDecryptCipher(privateKey, publicKey, algorithm);
      return new JCipherInputStream(cipher, in);
   }

   /**
    * 获得解密模式的{@link Cipher}
    * 
    * @param privateKey
    * @param publicKey
    * @param algorithm
    * @return
    */
   public static Cipher getDecryptCipher(byte[] privateKey, byte[] publicKey, String algorithm) {
      return getCipher(privateKey, publicKey, algorithm, Cipher.DECRYPT_MODE);
   }

   private static Cipher getCipher(byte[] privateKey, byte[] publicKey, String algorithm, int opmode) {
      // 生成本地密钥
      SecretKey secretKey = getSecretKey(privateKey, publicKey, algorithm);

      try {
         // 数据加密
         Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
         cipher.init(opmode, secretKey);
         return cipher;
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * 获得密钥
    * 
    * @param privateKey
    *           己方私钥
    * @param publicKey
    *           对方公钥
    * @param algorithm
    *           对称算法
    * @return
    */
   private static SecretKey getSecretKey(byte[] privateKey, byte[] publicKey, String algorithm) {
      try {
         KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
         X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
         PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

         PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);
         Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);

         KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory.getAlgorithm());
         keyAgree.init(priKey);
         keyAgree.doPhase(pubKey, true);

         // 生成本地密钥
         return keyAgree.generateSecret(algorithm);
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }
}
