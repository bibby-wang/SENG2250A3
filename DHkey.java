import java.security.*;
import javax.crypto.*;

public class DHkey{


	public static KeyPair partyKey(int keySize) {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
			keyPairGen.initialize(keySize);
			return keyPairGen.generateKeyPair();
		}catch(NoSuchAlgorithmException e) {
			throw new JCodecException(e);
		}
	}

}