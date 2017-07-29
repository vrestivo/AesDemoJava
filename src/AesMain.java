import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.SecretKeySpec;


/**
 * @author devbox
 *
 */
public class AesMain {
	
	private static String mMessage = "This is a test string";
	private static String mKey = "this_is_a_test_key";

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		//ECB AES
		String encrypted = AesEcbEncryption.ecrypt(mMessage, mKey);
		System.out.println("Sring to encrypt: " + mMessage);
		System.out.println("encrypted: " + encrypted);
		String decrypted = AesEcbEncryption.decrypt(encrypted, mKey);
		System.out.println("decrypted: " + decrypted + "\n\n");

		
		//CBC AES
		System.out.println("String to encrypt: " + mMessage);
		encrypted = AesCbcEncryption.encrypt(mMessage, mKey);
		System.out.println("cbc encrypted: " + encrypted + "\n\n");
		decrypted = AesCbcEncryption.decrypt(encrypted, mKey);
		System.out.println("cbc decrypted: " + decrypted);

    
		
		

	}

}
