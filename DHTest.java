

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
      System.out.println("ԭ����" + str);
      JEncoder encoder = JBase64.getEncoder();
      KeyPair keyPairA = JDH.initPartyAKey();
      byte[] keyPairAPrivate = keyPairA.getPrivate().getEncoded();
      byte[] keyPairAPublic = keyPairA.getPublic().getEncoded();
	  
      System.out.println("�׷�˽Կ��" + encoder.encodeToString(keyPairAPrivate, "UTF-8"));
      System.out.println("�׷���Կ��" + encoder.encodeToString(keyPairAPublic, "UTF-8"));
      KeyPair keyPairB = JDH.initPartyBKey(keyPairAPublic);
	  
      byte[] keyPairBPrivate = keyPairB.getPrivate().getEncoded();
      byte[] keyPairBPublic = keyPairB.getPublic().getEncoded();
      System.out.println("�ҷ�˽Կ��" + encoder.encodeToString(keyPairBPrivate, "UTF-8"));
      System.out.println("�ҷ���Կ��" + encoder.encodeToString(keyPairBPublic, "UTF-8"));
      for (JDHSymmetricalAlgorithm algorithm : JDHSymmetricalAlgorithm.values()) {
         System.out.println("-----------------------------------------");
         System.out.println("�Գ��㷨��" + algorithm.getName());
         byte[] encrypt = JDH.encrypt(str.getBytes(), keyPairAPrivate, keyPairBPublic, algorithm.getName());
         System.out.println("���ܣ�" + encoder.encodeToString(encrypt, "UTF-8"));
         System.out
               .println("���ܣ�" + new String(JDH.decrypt(encrypt, keyPairBPrivate, keyPairAPublic, algorithm.getName())));

         System.out.print("��������ܣ�" + file.getAbsolutePath());
         OutputStream out = JDH.wrap(new FileOutputStream(file), keyPairAPrivate, keyPairBPublic, algorithm.getName());
         out.write(str.getBytes());
         out.flush();
         out.close();
         System.out.println();
         System.out.print("���������ܣ�");
         InputStream in = JDH.wrap(new FileInputStream(file), keyPairBPrivate, keyPairAPublic, algorithm.getName());
         byte[] buffer = new byte[1024];
         int len = in.read(buffer);
         System.out.println(new String(buffer, 0, len));
      }
   }
}
