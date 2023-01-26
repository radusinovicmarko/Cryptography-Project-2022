package org.unibl.etf.crypto.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.keystore.BC;
import org.bouncycastle.jcajce.provider.symmetric.AES.KeyGen;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SymmetricCryptographyUtils {
	
	public static final String symmetricAlgorithm = "AES";
	public static final String symmetricAlgorithmWithPadding = "AES/ECB/PKCS5Padding";
	private static final String PBEAlgorithm = "PBKDF2WithHmacSHA256";
	public static final String symmetricKeyResultsPath = "./src/PKI/private/resultsKey.txt";
	public static final String symmetricKeyStegoPath = "./src/PKI/private/stegoKey.txt";
	private static final int iterationCount = 65536;
	private static final int keyLength = 128;

	private static SecretKey createSecretKey(String password) throws Exception {
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBEAlgorithm);
		KeySpec spec = new PBEKeySpec(password.toCharArray(), "12345678".getBytes(), iterationCount, keyLength);
		return new SecretKeySpec(keyFactory.generateSecret(spec).getEncoded(), symmetricAlgorithm);
	}
	
	public static SecretKey readSymemtricKey() {
		try (InputStream inStream = new FileInputStream(new File(symmetricKeyResultsPath))) {
			byte[] input = inStream.readAllBytes();
		    SecretKeyFactory skf = SecretKeyFactory.getInstance(symmetricAlgorithm, new BouncyCastleProvider());
		    return skf.generateSecret(new SecretKeySpec(input, symmetricAlgorithm));
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}

	public static void createSecretKey() {
		KeyGenerator keygen = null;
		try {
			keygen = KeyGenerator.getInstance(symmetricAlgorithm, new BouncyCastleProvider());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keygen.init(keyLength);
		SecretKey key = keygen.generateKey();
		try (FileOutputStream fos = new FileOutputStream(new File(symmetricKeyResultsPath))) {
			fos.write(key.getEncoded());
		}  catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static byte[] encrypt(byte[] input, String password) throws Exception {
		SecretKey key = createSecretKey(password);
		Cipher cipher = Cipher.getInstance(symmetricAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(input);
	}
	
	public static byte[] decrypt(byte[] input, String password) throws Exception {
		SecretKey key = createSecretKey(password);
		Cipher cipher = Cipher.getInstance(symmetricAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(input);
	}
}
