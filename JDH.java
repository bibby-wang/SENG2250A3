

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
 * Diffie-Hellman�㷨(D-H�㷨)����Կһ��Э�顣���ɹ�����Կ�������Ƶĵ����Diffie��Hellman�������һ��˼�롣
 * �򵥵�˵�������������û��ڹ���ý���Ͻ�����Ϣ������"һ��"�ġ����Թ������Կ�����仰˵�������ɼ׷�����һ����Կ����Կ��˽Կ����
 * �ҷ����ռ׷���Կ�����ҷ���Կ�ԣ���Կ��˽Կ�����Դ�Ϊ���ߣ���Ϊ���ݴ��䱣�ܻ�����ͬʱ˫��ʹ��ͬһ�ֶԳƼ����㷨����������Կ��SecretKey�������ݼ���
 * ���������ڻ�ͨ�˱�����Կ��SecretKey���㷨�󣬼���˫�������Լ��Ĺ�Կ��ʹ�öԷ��Ĺ�Կ�͸ղŲ�����˽Կ�������ݣ�
 * ͬʱ����ʹ�öԷ��Ĺ�Կ���Լ���˽Կ�����ݽ��ܡ��������Ǽ���˫��������������չΪ�෽��������ͨѶ����������������罻�����ݵİ�ȫͨѶ��
 * ���㷨Դ���й���ͬ�ඨ�����й���������
 * <ol>
 * <li>�׷�������Կ�Զ�������Կ�������ҷ�����˽Կ������˫��Լ�����ݼ����㷨���ҷ�ͨ���׷���Կ������Կ�Զ�������Կ�������׷�����˽Կ������</li>
 * <li>�׷�ʹ��˽Կ���ҷ���Կ��Լ�����ݼ����㷨����������Կ��Ȼ��ͨ��������Կ�������ݣ����͸��ҷ����ܺ�����ݣ��ҷ�ʹ��˽Կ���׷���Կ��
 * Լ�����ݼ����㷨����������Կ��Ȼ��ͨ��������Կ�����ݽ��ܡ�</li>
 * <li>�ҷ�ʹ��˽Կ���׷���Կ��Լ�����ݼ����㷨����������Կ��Ȼ��ͨ��������Կ�������ݣ����͸��׷����ܺ�����ݣ��׷�ʹ��˽Կ���ҷ���Կ��
 * Լ�����ݼ����㷨����������Կ��Ȼ��ͨ��������Կ�����ݽ��ܡ�</li>
 * </ol>
 * 
 * @author jianggujin
 * 
 */
public class JDH {

   private final static String ALGORITHM = "DH";

   /**
    * �Գ��㷨
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
    * ��ʼ���׷���Կ
    * 
    * @return
    */
   public static KeyPair initPartyAKey() {
      return initPartyAKey(1024);
   }

   /**
    * ��ʼ���׷���Կ
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
    * ��ʼ���ҷ���Կ
    * 
    * @param partyAPublicKey
    *           �׷���Կ
    * @return
    */
   public static KeyPair initPartyBKey(byte[] partyAPublicKey) {
      try {
         X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(partyAPublicKey);
         KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
         PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

         // �ɼ׷���Կ�����ҷ���Կ
         DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();

         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
         keyPairGenerator.initialize(dhParamSpec);

         return keyPairGenerator.generateKeyPair();
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * ����
    * 
    * @param data
    *           ��������
    * @param privateKey
    *           ����˽Կ
    * @param publicKey
    *           �Է���Կ
    * @param algorithm
    *           �Գ��㷨
    * @return
    */
   public static byte[] encrypt(byte[] data, byte[] privateKey, byte[] publicKey, String algorithm) {
      // ���ݼ���
      Cipher cipher = getEncryptCipher(privateKey, publicKey, algorithm);

      try {
         return cipher.doFinal(data);
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * �����������������������Ϊ���������
    * 
    * @param out
    * @param privateKey
    * @param publicKey
    * @param algorithm
    * @return
    */
   public static OutputStream wrap(OutputStream out, byte[] privateKey, byte[] publicKey, String algorithm) {
      // ���ݼ���
      Cipher cipher = getEncryptCipher(privateKey, publicKey, algorithm);

      return new JCipherOutputStream(cipher, out);
   }

   /**
    * ��ü���ģʽ��{@link Cipher}
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
    * ����
    * 
    * @param data
    *           ��������
    * @param privateKey
    *           ����˽Կ
    * @param publicKey
    *           �Է���Կ
    * @param algorithm
    *           �Գ��㷨
    * @return
    */
   public static byte[] decrypt(byte[] data, byte[] privateKey, byte[] publicKey, String algorithm) {
      // ���ݽ���
      Cipher cipher = getDecryptCipher(privateKey, publicKey, algorithm);
      try {
         return cipher.doFinal(data);
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * ������������ԭ������Ϊ��������������
    * 
    * @param in
    * @param privateKey
    * @param publicKey
    * @param algorithm
    * @return
    */
   public static InputStream wrap(InputStream in, byte[] privateKey, byte[] publicKey, String algorithm) {
      // ���ݽ���
      Cipher cipher = getDecryptCipher(privateKey, publicKey, algorithm);
      return new JCipherInputStream(cipher, in);
   }

   /**
    * ��ý���ģʽ��{@link Cipher}
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
      // ���ɱ�����Կ
      SecretKey secretKey = getSecretKey(privateKey, publicKey, algorithm);

      try {
         // ���ݼ���
         Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
         cipher.init(opmode, secretKey);
         return cipher;
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }

   /**
    * �����Կ
    * 
    * @param privateKey
    *           ����˽Կ
    * @param publicKey
    *           �Է���Կ
    * @param algorithm
    *           �Գ��㷨
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

         // ���ɱ�����Կ
         return keyAgree.generateSecret(algorithm);
      } catch (Exception e) {
         throw new JCodecException(e);
      }
   }
}
