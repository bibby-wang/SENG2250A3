

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;

import org.junit.Test;



public class DHTest {
   String str = "jianggujin";
   File file = new File(getClass().getSimpleName() + ".dat");

   @Test
   public void test() throws Exception {
      System.out.println("原串：" + str);
      JEncoder encoder = JBase64.getEncoder();
      KeyPair keyPairA = JDH.initPartyAKey();
      byte[] keyPairAPrivate = keyPairA.getPrivate().getEncoded();
      byte[] keyPairAPublic = keyPairA.getPublic().getEncoded();
	  
      System.out.println("甲方私钥：" + encoder.encodeToString(keyPairAPrivate, "UTF-8"));
      System.out.println("甲方公钥：" + encoder.encodeToString(keyPairAPublic, "UTF-8"));
      KeyPair keyPairB = JDH.initPartyBKey(keyPairAPublic);
	  
      byte[] keyPairBPrivate = keyPairB.getPrivate().getEncoded();
      byte[] keyPairBPublic = keyPairB.getPublic().getEncoded();
      System.out.println("乙方私钥：" + encoder.encodeToString(keyPairBPrivate, "UTF-8"));
      System.out.println("乙方公钥：" + encoder.encodeToString(keyPairBPublic, "UTF-8"));
      for (JDHSymmetricalAlgorithm algorithm : JDHSymmetricalAlgorithm.values()) {
         System.out.println("-----------------------------------------");
         System.out.println("对称算法：" + algorithm.getName());
         byte[] encrypt = JDH.encrypt(str.getBytes(), keyPairAPrivate, keyPairBPublic, algorithm.getName());
         System.out.println("加密：" + encoder.encodeToString(encrypt, "UTF-8"));
         System.out
               .println("解密：" + new String(JDH.decrypt(encrypt, keyPairBPrivate, keyPairAPublic, algorithm.getName())));

         System.out.print("输出流加密：" + file.getAbsolutePath());
         OutputStream out = JDH.wrap(new FileOutputStream(file), keyPairAPrivate, keyPairBPublic, algorithm.getName());
         out.write(str.getBytes());
         out.flush();
         out.close();
         System.out.println();
         System.out.print("输入流解密：");
         InputStream in = JDH.wrap(new FileInputStream(file), keyPairBPrivate, keyPairAPublic, algorithm.getName());
         byte[] buffer = new byte[1024];
         int len = in.read(buffer);
         System.out.println(new String(buffer, 0, len));
      }
   }
}
