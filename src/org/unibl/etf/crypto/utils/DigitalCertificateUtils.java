package org.unibl.etf.crypto.utils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.unibl.etf.crypto.Tuple;

public class DigitalCertificateUtils {
	
	private static final String certStandard = "X.509";
	public static final String CA1CertPath = "./src/PKI/subCA1/CA1Cert.pem";
	public static final String CA2CertPath = "./src/PKI/subCA2/CA2Cert.pem";
	public static final String CA1PrivateKeyPath = "./src/PKI/subCA1/private/CA1PrivateKey.der";
	public static final String CA2PrivateKeyPath = "./src/PKI/subCA2/private/CA2PrivateKey.der";
	public static final PrivateKey CA1PrivateKey;
	public static final PrivateKey CA2PrivateKey;
	private static final String serialCA1Path = "./src/PKI/subCA1/serial.txt";
	private static final String serialCA2Path = "./src/PKI/subCA2/serial.txt";
	public static final String certsCA1FolderPath = "./src/PKI/subCA1/certs/";
	public static final String certsCA2FolderPath = "./src/PKI/subCA2/certs/";
	public static final X509Certificate CA1Cert;
	public static final X509Certificate CA2Cert;
	public static final String signingAlgorithm = "SHA256withRSA";
	
	static {
		CA1Cert = readCertificate(new File(CA1CertPath));
		CA2Cert = readCertificate(new File(CA2CertPath));
		CA1PrivateKey = AsymmetricKeysUtils.readPrivateKey(new File(CA1PrivateKeyPath));
		CA2PrivateKey = AsymmetricKeysUtils.readPrivateKey(new File(CA2PrivateKeyPath));
	}
	
	public static X509Certificate readCertificate2(File file) {
		try (PemReader reader = new PemReader(new FileReader(file))) {
			PemObject pemCert = reader.readPemObject();
			CertificateFactory certFactory = CertificateFactory.getInstance(certStandard);
			X509Certificate cert = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(pemCert.getContent()));
			return cert;
		} catch (IOException | CertificateException e) {
			System.err.println(e.getMessage());
			return null;
		}
	}
	
	public static X509Certificate readCertificate(File file) {
		try (InputStream inStream = new FileInputStream(file)) {
		    CertificateFactory cf = CertificateFactory.getInstance(certStandard);
		    X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
		    return cert;
		} catch (IOException | CertificateException e) {
			System.err.println(e.getMessage());
			return null;
		}
	}
	
	public static Tuple<String, PrivateKey> createAndSignCertificateRequest(String userName, String password, String organization, String organizationalUnit,
			String locality, String state, String country) throws Exception {
		String subjectInfo = createSubjectInfo(userName, organization, organizationalUnit, locality, state, country);
		KeyPair keyPair = AsymmetricKeysUtils.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(/*ASN1Sequence.getInstance(publicKey)*/publicKey.getEncoded());
		PKCS10CertificationRequestBuilder certReqBuilder = new PKCS10CertificationRequestBuilder(new X500Name(subjectInfo), subjectPublicKeyInfo);
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(signingAlgorithm);
		PrivateKey signerPrivateKey = null;
		boolean signer = new Random().nextBoolean();
		String certFolderPath = null;
		if (signer) {
			signerPrivateKey = CA1PrivateKey;
			certFolderPath = certsCA1FolderPath;
		}
		else {
			signerPrivateKey = CA2PrivateKey; 
			certFolderPath = certsCA2FolderPath;
		}
		ContentSigner contentSigner = csBuilder.build(signerPrivateKey);
		PKCS10CertificationRequest request = certReqBuilder.build(contentSigner);
		X509Certificate certificate = signCertificateRequest(request, subjectPublicKeyInfo, signer, contentSigner);
		String certificatePath = certFolderPath + userName + ".der";
		writeCertificate(certificate, new File(certificatePath));
		return new Tuple<>(certificatePath, privateKey);
	}
	
	private static void writeCertificate2(X509Certificate certificate, File file) {
		try (PemWriter writer = new PemWriter(new FileWriter(file))) {
	    	writer.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));;
	    } catch (IOException | CertificateEncodingException e) {
	    	System.err.println(e.getMessage());
		}
	}
	
	public static void writeCertificate(X509Certificate certificate, File file) {
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(certificate.getEncoded());
		} catch (CertificateEncodingException | IOException e) {
			System.err.println(e.getMessage());
		}
	}
	
	private static String getNextSerial(File file) throws IOException, NumberFormatException {
		String nextSerialNumber = null;
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			nextSerialNumber = br.readLine();
		}
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
			Integer next = Integer.parseInt(nextSerialNumber) + 1;
			bw.write(next.toString());
		}
		return nextSerialNumber;
	}

	public static X509Certificate signCertificateRequest(PKCS10CertificationRequest request, SubjectPublicKeyInfo subjectPublicKeyInfo, 
			boolean signer, ContentSigner contentSigner) throws NumberFormatException, IOException {
		X509Certificate CASigner = null;
		String serialNumber = null;
		if (signer) {
			CASigner = CA1Cert;
			serialNumber = getNextSerial(new File(serialCA1Path));
		}
		else {
			CASigner = CA2Cert;
			serialNumber = getNextSerial(new File(serialCA2Path));
		}
		X500Name issuer = new X500Name(CASigner.getSubjectDN().getName());
		Calendar now = Calendar.getInstance();
		Date validFromDate = now.getTime();
		now.add(Calendar.YEAR, 1);
		Date validToDate = now.getTime();
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, new BigInteger(serialNumber),
				validFromDate, validToDate, request.getSubject(), subjectPublicKeyInfo);
		KeyUsage usage = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement);
		certBuilder.addExtension(Extension.keyUsage, false, usage);
		certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);
		try {
			CertificateFactory certFactory = CertificateFactory.getInstance(certStandard);
			X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(certificateHolder.toASN1Structure().getEncoded()));
			return certificate; 
		} catch (CertificateException | IOException e) {
			System.err.println(e.getMessage());
			return null;
		}
	}
	
	private static String createSubjectInfo(String commonName, String organization, String organizationalUnit,
			String locality, String state, String country) {
		StringBuilder sb = new StringBuilder();
		sb.append("CN=");
		sb.append(commonName);
		sb.append(", O=");
		sb.append(organization);
		sb.append(", OU=");
		sb.append(organizationalUnit);
		sb.append(", L=");
		sb.append(locality);
		sb.append(", ST=");
		sb.append(state);
		sb.append(", C=");
		sb.append(country);
		return sb.toString();
	}
	
	public static void verifyCertficate(X509Certificate certificate) throws Exception {
		String issuerName = certificate.getIssuerDN().getName();
		PublicKey pubKey = null;
		if ("SUB_CA_1".equals(issuerName.substring(issuerName.indexOf("CN=") + 3))) {
			pubKey = CA1Cert.getPublicKey();
		}
		else
			pubKey = CA2Cert.getPublicKey();
		certificate.verify(pubKey);
	}
	
	public static void certificateValidity(X509Certificate certificate) throws Exception {
		certificate.checkValidity();
	}
}
