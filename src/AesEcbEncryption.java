import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 * taken from 
 * http://howtodoinjava.com/security/java-aes-encryption-example/
 *
 */
public class AesEcbEncryption {


	private final static String mDigestAlgo = "SHA-1";
	private final static String AES = "AES";
	private static byte[] mKeyBytes;
	private static byte[] mDigestedKeyBytes;
	private static final String UTF = "UTF-8";
	private static SecretKeySpec mSecretKeySpec;
	private static final String CIPHER_SPEC = "AES/ECB/PKCS5Padding";

	public static void setKey(String myKey) {
		try {
			mKeyBytes = myKey.getBytes(UTF);
			MessageDigest digest = MessageDigest.getInstance(mDigestAlgo);
			mDigestedKeyBytes = digest.digest(mKeyBytes);
			mKeyBytes = Arrays.copyOf(mKeyBytes, 16);
			mSecretKeySpec = new SecretKeySpec(mKeyBytes, AES);
			
			//TODO delete
			//System.out.println(mKeyBytes.toString());
			//System.out.println(mDigestedKeyBytes.toString());

		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	/**
	 * encrypts a given string with a given key
	 * @param strToEncrypt
	 * @param secret
	 * @return
	 */
	public static String ecrypt(String strToEncrypt, String secret) {
		
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
			cipher.init(Cipher.ENCRYPT_MODE, mSecretKeySpec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(UTF)));
			
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
public static String decrypt(String strToDecrypt, String secret) {
	
	try {
	setKey(secret);
	Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
	cipher.init(Cipher.DECRYPT_MODE, mSecretKeySpec);
	return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
	
	} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InvalidKeyException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IllegalBlockSizeException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (BadPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	return null;
}
	
	
}
