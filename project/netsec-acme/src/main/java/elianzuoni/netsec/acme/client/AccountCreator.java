package elianzuoni.netsec.acme.client;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.logging.Logger;

import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.FlatJwsObject;
import elianzuoni.netsec.acme.jose.JwkObject;

class AccountCreator {
	
	private String url;
	private String nonce;
	private String crv;
	private String signAlgoBCName;
	private String signAlgoAcmeName;
	private KeyPair keypair;
	private String accountUrl;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AccountCreator");
	
	/**
	 * @param url the server's endpoint for creating accounts
	 * @param nonce the last Replay-Nonce value received
	 */
	AccountCreator(String url, String nonce) throws NoSuchAlgorithmException, 
					NoSuchProviderException, InvalidAlgorithmParameterException {
		super();
		this.url = url;
		this.nonce = nonce;
	}

	String getAccountUrl() {
		return accountUrl;
	}

	String getNextNonce() {
		return nextNonce;
	}
	
	void setKeypair(KeyPair keypair) {
		this.keypair = keypair;
	}

	void setCrv(String crv) {
		this.crv = crv;
	}

	void setSignAlgoBCName(String signAlgoBCName) {
		this.signAlgoBCName = signAlgoBCName;
	}

	void setSignAlgoAcmeName(String signAlgoAcmeName) {
		this.signAlgoAcmeName = signAlgoAcmeName;
	}

	/**
	 * Creates a new account by sending a POST request to the specified endpoint on
	 * the server.
	 * @throws NoSuchProviderException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	void createAccount() throws IOException, InvalidKeyException, SignatureException, 
								NoSuchAlgorithmException, NoSuchProviderException, 
								InvalidAlgorithmParameterException {		
		// Connect to the newAccount endpoint of the ACME server
		logger.fine("Connecting to newAccount endpoint at URL " + url);
		HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
		
		// Set the request to POST and set its headers
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		conn.addRequestProperty("Content-Type", "application/jose+json");
		
		// Build the request body
		JsonObject reqBody = buildReqBody();
		
		// Fire the request
		conn.connect();
		
		// Write the request body
		conn.getOutputStream().write(reqBody.toString().getBytes());

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_CREATED);
		
		// Get the account URL
		accountUrl = HttpUtils.getRequiredHeader(conn, "Location");
		logger.fine("Account URL: " + accountUrl);
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return;
	}

	/**
	 * Only builds the JWS body of the POST request
	 */
	private JsonObject buildReqBody() throws SignatureException, InvalidKeyException, 
											NoSuchAlgorithmException {
		FlatJwsObject body = new FlatJwsObject();
		
		// Build JWS header
		body.addAlgHeader(signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addJwkHeader(JwkObject.encodeEcPublicKey((ECPublicKey)keypair.getPublic(), crv));
		
		// Build JWS payload
		body.addPayloadEntry("termsOfServiceAgreed", JsonValue.TRUE);	// Not really necessary
		
		return body.finalise(keypair.getPrivate(), signAlgoBCName);
	}
}
