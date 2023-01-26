package org.unibl.etf.crypto.utils;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;

public class AsymmetricKeysUtils {
	
	public static final String asymmetricAlgorithm = "RSA";
	public static final int asymmetricKeyLength = 4096;
	
	public static PrivateKey readPrivateKey(File file) {
		try (DataInputStream dis = new DataInputStream(new FileInputStream(file))) {
			byte[] keyBytes = new byte[(int)file.length()];
			dis.readFully(keyBytes);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(asymmetricAlgorithm);
			return keyFactory.generatePrivate(spec);
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.err.println(e.getMessage() + " aaa ");
			return null;
		}
	}
	
	public static void writePrivateKey(File file, PrivateKey privateKey) {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(spec.getEncoded());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(asymmetricAlgorithm);
		keyGen.initialize(asymmetricKeyLength);
		return keyGen.generateKeyPair();
	}
}
