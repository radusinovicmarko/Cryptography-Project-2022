package org.unibl.etf.crypto.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CRLUtils {
	
	public static final String subCA1CRLPath = "./src/PKI/subCA1/crl/CRL.der";
	public static final String subCA2CRLPath = "./src/PKI/subCA2/crl/CRL.der";
	public static final String rootCACRLPath = "./src/PKI/crl/CRL.der";
	public static final String CRLStandard = "X.509";
	
	private static X509CRL subCA1CRL;
	private static X509CRL subCA2CRL;
	private static X509CRL rootCACRL;
	
	static {
		subCA1CRL = readCRL(new File(subCA1CRLPath));
		subCA2CRL = readCRL(new File(subCA2CRLPath));
		rootCACRL = readCRL(new File(rootCACRLPath));
	}

	public static X509CRL readCRL(File file) {
		try (InputStream inStream = new FileInputStream(file)) {
		    CertificateFactory cf = CertificateFactory.getInstance(CRLStandard);
		    X509CRL crl = (X509CRL)cf.generateCRL(inStream);
		    return crl;
		} catch (IOException | CertificateException | CRLException e) {
			System.err.println(e.getMessage());
			return null;
		}
	}
	
	public static void writeCRL(File file, X509CRL crl) {
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(crl.getEncoded());
		} catch (IOException | CRLException e) {
			System.err.println(e.getMessage());
		}
	}

	public static void revokeCertificate(X509Certificate certificate) throws OperatorCreationException, CRLException {
		String certificateIssuerDN = certificate.getIssuerDN().getName();
		String certificateIssuerName = certificateIssuerDN.substring(certificateIssuerDN.indexOf("CN=") + 3);
		X509CRL targetCRL = null;
		PrivateKey pk = null;
		String CRLIssuer = subCA1CRL.getIssuerDN().getName();
		String CRLIssuerName = CRLIssuer.substring(3, CRLIssuer.indexOf(","));
		if (certificateIssuerName.equals(CRLIssuerName)) {
			targetCRL = subCA1CRL;
			pk = DigitalCertificateUtils.CA1PrivateKey;
		}
		else {
			targetCRL = subCA2CRL;
			pk = DigitalCertificateUtils.CA2PrivateKey;
		}
		X509CRLHolder crlHolder = null;
		try {
			crlHolder = new X509CRLHolder(targetCRL.getEncoded());
		} catch (CRLException | IOException e) {
			e.printStackTrace();
		}
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlHolder);
		crlBuilder.addCRLEntry(certificate.getSerialNumber(), new Date(), 5);
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(targetCRL.getSigAlgName());
		ContentSigner signer = csBuilder.build(pk);
		X509CRLHolder newCRLHolder = crlBuilder.build(signer);
		if (certificateIssuerName.equals(CRLIssuerName)) {
			subCA1CRL = new JcaX509CRLConverter().getCRL(newCRLHolder);
			writeCRL(new File(subCA1CRLPath), subCA1CRL);
		}
		else {
			subCA2CRL = new JcaX509CRLConverter().getCRL(newCRLHolder);
			writeCRL(new File(subCA2CRLPath), subCA2CRL);
		}
	}
	
	public static boolean certificateRevoked(X509Certificate certificate) {
		String issuerName = certificate.getIssuerDN().getName();
		X509CRL rootCACRL = CRLUtils.rootCACRL;
		X509CRL subCACRL = null;
		X509Certificate subCACert = null;
		if ("SUB_CA_1".equals(issuerName.substring(issuerName.indexOf("CN=") + 3))) {
			subCACRL = CRLUtils.subCA1CRL;
			subCACert = DigitalCertificateUtils.CA1Cert;
		}
		else {
			subCACRL = CRLUtils.subCA2CRL;
			subCACert = DigitalCertificateUtils.CA2Cert;
		}
		if (subCACRL.getRevokedCertificates() != null)
			for (X509CRLEntry entry : subCACRL.getRevokedCertificates())
				if (entry.getSerialNumber().equals(certificate.getSerialNumber()))
					return true;
		return false;
	}
}
