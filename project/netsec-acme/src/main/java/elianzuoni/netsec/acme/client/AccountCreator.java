package elianzuoni.netsec.acme.client;

import java.net.HttpURLConnection;
import java.security.interfaces.ECPublicKey;
import java.util.logging.Logger;

import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.AcmeUtils;
import elianzuoni.netsec.acme.utils.HttpUtils;
import elianzuoni.netsec.acme.jose.Jwk;

class AccountCreator {
	
	private String url;
	private String nonce;
	private JwsParams jwsParams;
	private String accountUrl;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AccountCreator");
	
	/**
	 * @param url the server's endpoint for creating accounts
	 * @param nonce the last Replay-Nonce value received
	 */
	AccountCreator(String url, String nonce, JwsParams jwsParams) {
		super();
		this.url = url;
		this.nonce = nonce;
		this.jwsParams = jwsParams;
	}

	String getAccountUrl() {
		return accountUrl;
	}

	String getNextNonce() {
		return nextNonce;
	}

	/**
	 * Creates a new account by sending a POST request to the specified endpoint on
	 * the server.
	 */
	void createAccount() throws Exception {		
		// Connect to the newAccount endpoint of the ACME server
		logger.fine("Connecting to newAccount endpoint at URL " + url);
		HttpsURLConnection conn = AcmeUtils.sendRequest(url, nonce, jwsParams, buildReqBody());

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
	private JsonObject buildReqBody() throws Exception {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(jwsParams.signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addJwkHeader(Jwk.fromEcPublicKey((ECPublicKey)jwsParams.accountKeypair.getPublic(), 
												jwsParams.crv));
		
		// Build JWS payload
		body.addPayloadEntry("termsOfServiceAgreed", JsonValue.TRUE);	// Not really necessary
		
		return body.finalise(jwsParams.accountKeypair.getPrivate(), jwsParams.signAlgoBCName);
	}
}
