package elianzuoni.netsec.acme.client;

import java.io.FileInputStream;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.AcmeUtils;
import elianzuoni.netsec.acme.utils.HttpUtils;

class CertificateRevoker {
	
	private String url;
	private String nonce;
	private String keystoreFilepath;
	private String keystorePassword;
	private JwsParams jwsParams;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.CertificateRevoker");
	
	/**
	 * @param url the server's endpoint for placing orders
	 * @param nonce the last Replay-Nonce value received
	 */
	CertificateRevoker(String url, String nonce, JwsParams jwsParams) {
		super();
		this.url = url;
		this.nonce = nonce;
		this.jwsParams = jwsParams;
	}

	void setKeystoreInfo(String keystoreFilepath, String keystorePassword) {
		this.keystoreFilepath = keystoreFilepath;
		this.keystorePassword = keystorePassword;
	}

	String getNextNonce() {
		return nextNonce;
	}

	/**
	 * Revokes certificate
	 */
	void revokeCertificate() throws Exception {		
		// Connect to the certRevoke endpoint of the ACME server
		logger.fine("Connecting to certRevoke endpoint at URL " + url);
		HttpsURLConnection conn = AcmeUtils.sendRequest(url, nonce, jwsParams, buildReqBody());

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_OK);
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return;
	}

	/**
	 * Only builds the JWS body of the POST request
	 */
	private JsonObject buildReqBody() throws Exception {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(jwsParams.signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addKidHeader(jwsParams.accountUrl);
		
		// Load keystore
		logger.fine("Loading keystore " + keystoreFilepath);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(keystoreFilepath), keystorePassword.toCharArray());
        
        // Take the first certificate in the chain, and base64url-encode its DER representation
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("any_alias");
        byte certBytes[] = cert.getEncoded();
        String certEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(certBytes);
		
		// Build JWS payload
		body.addPayloadEntry("certificate", Json.createValue(certEncoded));
		
		return body.finalise(jwsParams.accountKeypair.getPrivate(), jwsParams.signAlgoBCName);
	}
}
