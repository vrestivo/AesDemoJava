import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCbcEncryption {

	// Constants
	private static final String DIGEST_ALGORITHM = "SHA-1";
	//it is reccommended to use fully qualified spec
	private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
	private static final String AES = "AES";
	private static final String UTF = "UTF-8";
	private static final int AES_BLOCK_SIZE = 16;

	private static byte[] mKeyBytes;
	private static byte[] mDigestedKeyBytes;
	private static SecretKeySpec mSecretKeySpec;
	private static IvParameterSpec mIvSpec;
	private static byte[] mCipherTextBytes;
	private static byte[] mIvRandomizedBytes;
	private static byte[] mIvRetrievedBytes;
	
	
	/**
	 * 
	 * this class is used to demonstrate AES CBC password-based encryption/decryption
	 * NOTE: uncomment debugging statements if you are curious to see how data changes
	 * 
	 * Encryption steps 
	 * 1) get encryption and encryption key (password) 
	 * 2) generate
	 * Initialization vector (IV) in IvParameterSpec format NOTE: IVs are required
	 * for CBC based encryption and are usually the size of the CBC block 
	 * 2-a) get a byte array of CBC block size 2-b) fill the array with random bytes 
	 * 2-c) create instance of IvParameterSpec initiated with IV from step 2-c 
	 * 3) Create SecretKeySpec 
	 * 3-a) convert String key into a UTF-8 encoded byte array 
	 * 3-b) hash the key byte array using message digest algorithm 
	 * 3-c) extract the first cipher block sized part of the digested key 
	 * 3-d) created a SecretKeySpec using the extracted cipher block sized key 
	 * 4) Create and initialize a Cipher instance 
	 * 4-a) Create a Cipher instance 
	 * 4-b) Initialize the Cipher instance by specifying Mode(Encryption/Decryption), key, and IV.
	 * 4-c) Prepend the IV vector to the ciphertext output NOTE: IV will be needed for decryption. 
	 * 4-d) Generate ciphertext by calling doFinal() 
	 * 4-d-a) Optionally can use CipherOutputStream 
	 * 4-e) convert the output to whatever format you like
	 * 
	 * Decryption steps are in reverse :) 
	 * 
	 * @param myKey - password
	 * @param mode - encryption or decryption
	 */
	public static boolean setKey(String myKey, int mode) {
		boolean result = false;
		try {
			// NOTE CBC ciphers require Initialization Vectors (IVs);

			// IV byte array which to be seeded with random data
			byte[] iv = new byte[AES_BLOCK_SIZE];
			
			//if we are encrypting date, generate a new IV
			if (mode == Cipher.ENCRYPT_MODE) {
				// cryptographically secure random number generator (not predictable)
				SecureRandom secRandom = new SecureRandom();
				
				// create and seed the IV byte array with random bytes
				mIvRandomizedBytes = new byte[AES_BLOCK_SIZE];
				secRandom.nextBytes(mIvRandomizedBytes);
				//System.out.println("IV Bytes enc: " + mIvRandomizedBytes);
				
				mIvSpec = new IvParameterSpec(mIvRandomizedBytes);
			}
			else if (mode == Cipher.DECRYPT_MODE){
				if(mCipherTextBytes!=null && mCipherTextBytes.length>0) {
					
					//get the IV ad copy into mIvRetrievedBytes
					mIvRetrievedBytes = new byte[AES_BLOCK_SIZE];
					System.arraycopy(mCipherTextBytes, 0, mIvRetrievedBytes, 0, AES_BLOCK_SIZE);
					//System.out.println("DEBUG: rawIv: " + mIvRetrievedBytes + " size: " + mIvRetrievedBytes.length);
					
					//set the IvParameterSpec
					mIvSpec = new IvParameterSpec(mIvRetrievedBytes);
					//System.out.println("DEBUG: mIvBytes retrieved" + Arrays.toString(mIvSpec.getIV()));
				}
				//abort if the data being decrypted is empty
				else {
					return false;
				}
			}
			//abort if incorrect mode is passed
			else {
				return false;
			}
			
			//System.out.println("DEBUG: mIvBytes getIV" + Arrays.toString(mIvSpec.getIV()));
			
			// convert key String into byte array
			mKeyBytes = myKey.getBytes(UTF);

			//get sha1 algorithm, which is used to has the passed password
			MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
			//hash the password
			mDigestedKeyBytes = digest.digest(mKeyBytes);
			//System.out.println("DEBUG: mDigestedKeyBytes " + Arrays.toString(mDigestedKeyBytes));


			// use only the 16 bytes of the "digested" password
			// It has to be 16 bytes (128 bits) because that is the size of a single
			// AES CBC block 
			byte[] key = Arrays.copyOf(mKeyBytes, AES_BLOCK_SIZE);
			//System.out.println("DEBUG: mKeyBytes " + Arrays.toString(key));

			// the key is required to be in the SecretKeySpec format
			mSecretKeySpec = new SecretKeySpec(key, AES);

			//return true on success
			result = true;


		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return result;

	}

	/**
	 * encrypts a given string with a given key
	 * 
	 * @param strToEncrypt
	 * @param secret
	 * @return
	 */
	public static String encrypt(String strToEncrypt, String secret) {
		// if the key was successfully generated, then encrypt data
		if (strToEncrypt != null && !strToEncrypt.isEmpty() && secret != null && !secret.isEmpty()) {
			if (setKey(secret, Cipher.ENCRYPT_MODE)) {
				try {
					Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
					cipher.init(Cipher.ENCRYPT_MODE, mSecretKeySpec, mIvSpec);
					//System.out.println("DEBUG: mIvBytes cipher enc" + Arrays.toString(cipher.getIV()));
					
					byte[] cipherBytes = cipher.doFinal(strToEncrypt.getBytes(UTF));
					//System.out.println("DEBUG: cipher bytes enc " + Arrays.toString(cipherBytes));
					
					byte[] finalBytes = new byte[AES_BLOCK_SIZE + cipherBytes.length];
					//prepend IV to the final byte array
					System.arraycopy(cipher.getIV(), 0, finalBytes, 0, AES_BLOCK_SIZE);
					System.arraycopy(cipherBytes, 0, finalBytes, AES_BLOCK_SIZE, cipherBytes.length);
					//System.out.println("DEBUG: FINAL bytes enc " + Arrays.toString(finalBytes));

					return Base64.getEncoder().encodeToString(finalBytes);
					
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
				} catch (InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return null;
	}

	public static String decrypt(String strToDecrypt, String secret) {
		//
		if (strToDecrypt != null && !strToDecrypt.isEmpty() && secret != null && !secret.isEmpty()) {
			mCipherTextBytes = Base64.getDecoder().decode(strToDecrypt);
			//System.out.println("DEBUG: mCipherTextBytess dec " + Arrays.toString(mCipherTextBytes));

			
			try {
				// if the key was successfully generated, then encrypt data
				if (setKey(secret, Cipher.DECRYPT_MODE)){
					Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
				
					cipher.init(Cipher.DECRYPT_MODE, mSecretKeySpec, mIvSpec);
					//System.out.println("DEBUG: mIvBytes cipher dec" + Arrays.toString(cipher.getIV()));
				
					byte[] cipherTextBytes = new byte [mCipherTextBytes.length - AES_BLOCK_SIZE];
					System.arraycopy(mCipherTextBytes, AES_BLOCK_SIZE, cipherTextBytes, 0, mCipherTextBytes.length-AES_BLOCK_SIZE);
					//System.out.println("DEBUG: cipher bytes dec " + Arrays.toString(cipherTextBytes));
						
					return new String(cipher.doFinal(cipherTextBytes));
				}

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
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		return null;
	}

}
