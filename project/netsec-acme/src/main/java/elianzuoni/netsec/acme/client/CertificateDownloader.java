package elianzuoni.netsec.acme.client;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.AcmeUtils;
import elianzuoni.netsec.acme.utils.HttpUtils;

public class CertificateDownloader {
	
	private String certUrl;
	private KeyPair certKeypair;
	private String certKeystoreAlias;
	private String httpsRootDir;
	private String keystoreFilename;
	private String certFilename;
	private String nonce;
	private JwsParams jwsParams;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.CertificateDownloader");
	
	
	CertificateDownloader(String certUrl, String nonce, JwsParams jwsParams) {
		super();
		this.certUrl = certUrl;
		this.nonce = nonce;
		this.jwsParams = jwsParams;
	}

	void setCertKeystoreAlias(String certKeystoreAlias) {
		this.certKeystoreAlias = certKeystoreAlias;
	}

	void setKeystoreFilename(String keystoreFilename) {
		this.keystoreFilename = keystoreFilename;
	}

	void setHttpsRootDir(String httpsRootDir) {
		this.httpsRootDir = httpsRootDir;
	}

	void setCertFilename(String certFilename) {
		this.certFilename = certFilename;
	}

	void setCertKeypair(KeyPair certKeypair) {
		this.certKeypair = certKeypair;
	}

	String getNextNonce() {
		return nextNonce;
	}
	
	/**
	 * Downloads the certificate into the keystore file and the cert file
	 */
	void downloadCertificate() throws Exception {
		byte certBytes[] = retrieveCertificate();
		storeKeystore(certBytes, certKeypair.getPrivate());
		storeCertificates(certBytes);
		
		return;
	}

	/**
	 * Retrieves the certificate located at the specified URL
	 */
	private byte[] retrieveCertificate() throws Exception {		
		// Connect to the certificate endpoint of the ACME server
		logger.fine("Connecting to certificate endpoint at URL " + certUrl);
		HttpsURLConnection conn = AcmeUtils.doPostAsGet(certUrl, nonce, jwsParams);

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_OK);
		
		// Get the certificate
		byte cert[] = conn.getInputStream().readAllBytes();
		logger.fine("Certificate:\n" + new String(cert));
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return cert;
	}
	
	private void storeKeystore(byte[] certBytes, PrivateKey certSecretKey) throws Exception {
		// Parse certificate chain
		PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(certBytes)));
		List<Certificate> certChain = new LinkedList<Certificate>();
		X509CertificateHolder certHolder;
		while((certHolder = (X509CertificateHolder)pemParser.readObject()) != null) {
			X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
				          .generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
			certChain.add(cert);
		}
		logger.fine("Parsed certificate chain of length " + certChain.size() + ":\n" + certChain);

		// Create the keystore with the secret key and the public key cert
	    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	    keystore.load(null, null);
	    keystore.setKeyEntry(certKeystoreAlias, certSecretKey, null, 
	    						certChain.toArray(new Certificate[0]));
	    logger.fine("Created keystore");
		
		// Create file, if not yet existent
	    String keystoreFilepath = httpsRootDir + keystoreFilename;
		new File(keystoreFilepath).createNewFile();

	    // Store away the keystore
	    FileOutputStream fos = new FileOutputStream(keystoreFilepath, false);
	    keystore.store(fos, "barf".toCharArray());
	    logger.fine("Stored away keystore");
	    
	    return;
	}

	private void storeCertificates(byte[] certBytes) throws Exception {
		String certFilepath = httpsRootDir + certFilename;
		
		// Create file, if not yet existent
		new File(certFilepath).createNewFile();
		
		// Write the certificates onto the file
		FileWriter certsWriter = new FileWriter(certFilepath, false);
		certsWriter.write(new String(certBytes));
		certsWriter.close();
		
		// No need to inform our https server
		
		return;
	}
}
