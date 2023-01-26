package org.unibl.etf.crypto.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;

public class DigitalEnvelopeUtils {
	
	public static void createDigitalEnvelope(String path) throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance(SymmetricCryptographyUtils.symmetricAlgorithm);
		SecretKey symmetricKey = keyGen.generateKey();
		PublicKey pubKey = DigitalCertificateUtils.CA1Cert.getPublicKey();
		Cipher asymmetricCipher = Cipher.getInstance(AsymmetricKeysUtils.asymmetricAlgorithm);
		asymmetricCipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] de = asymmetricCipher.doFinal(symmetricKey.getEncoded());
		try (FileOutputStream fos = new FileOutputStream(new File(path))) {
			fos.write(de);
		}
	}
	
	private static SecretKey readSecretKey(String path) throws Exception {
		byte[] de = null;
		try (FileInputStream fis = new FileInputStream(new File(path))) {
			de = fis.readAllBytes();
		}
		Cipher asymmetricCipher = Cipher.getInstance(AsymmetricKeysUtils.asymmetricAlgorithm);
		asymmetricCipher.init(Cipher.DECRYPT_MODE, DigitalCertificateUtils.CA1PrivateKey);
		byte[] keyByte =  asymmetricCipher.doFinal(de);
		SecretKey key = new SecretKeySpec(keyByte, SymmetricCryptographyUtils.symmetricAlgorithm);
		return key;
	}
	
	public static byte[] encrypt(byte[] input, String keyPath) throws Exception {
		SecretKey secretKey = readSecretKey(keyPath);
		Cipher cipher = Cipher.getInstance(SymmetricCryptographyUtils.symmetricAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return java.util.Base64.getEncoder().encode(cipher.doFinal(input));
	}
	
	public static byte[] decrypt(byte[] input, String keyPath) throws Exception {
		SecretKey secretKey = readSecretKey(keyPath);
		Cipher cipher = Cipher.getInstance(SymmetricCryptographyUtils.symmetricAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		return cipher.doFinal(java.util.Base64.getDecoder().decode(input));
	}

}
