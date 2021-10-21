package elianzuoni.netsec.acme.client;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.FlatJwsObject;

class AuthorisationsRetriever {
	
	private Collection<String> urls;
	private String nonce;
	private String signAlgoBCName;
	private String signAlgoAcmeName;
	private KeyPair keypair;
	private String accountUrl;
	private Collection<JsonObject> authorisations;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AuthorisationsRetriever");
	
	/**
	 * @param url the server's endpoint for placing orders
	 * @param nonce the last Replay-Nonce value received
	 */
	AuthorisationsRetriever(Collection<String> urls, String nonce) {
		super();
		this.urls = urls;
		this.nonce = nonce;
		this.authorisations = new LinkedList<JsonObject>();
	}

	void setCrypto(KeyPair keypair, String signAlgoBCName, String signAlgoAcmeName) {
		this.keypair = keypair;
		this.signAlgoBCName = signAlgoBCName;
		this.signAlgoAcmeName = signAlgoAcmeName;
	}

	void setAccountUrl(String accountUrl) {
		this.accountUrl = accountUrl;
	}

	Collection<JsonObject> getAuthorisations() {
		return authorisations;
	}

	String getNextNonce() {
		return nextNonce;
	}

	/**
	 * Retrieves all authorisation objects by sending a POST-as-GET request to the specified 
	 * endpoints on the server.
	 */
	void retrieveAuthorisations() throws InvalidKeyException, SignatureException,
											NoSuchAlgorithmException, NoSuchProviderException, 
											InvalidAlgorithmParameterException, IOException {
		// Populate the map
		for(String url : urls) {
			authorisations.add(retrieveAuthorisation(url));
			// Shift back the nonce for the next request
			nonce = nextNonce;
		}
		
		return;
	}
	
	/**
	 * Retrieves the authorisation located at the specified URL
	 */
	private JsonObject retrieveAuthorisation(String url) throws IOException, InvalidKeyException, 
														SignatureException, NoSuchAlgorithmException, 
														NoSuchProviderException, 
														InvalidAlgorithmParameterException {		
		// Connect to the authorisation endpoint of the ACME server
		logger.fine("Connecting to authorisation endpoint at URL " + url);
		HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
		
		// Set the request to POST and set its headers
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		conn.addRequestProperty("Content-Type", "application/jose+json");
		
		// Build the request body
		JsonObject reqBody = buildReqBody(url);
		
		// Fire the request
		conn.connect();
		
		// Write the request body
		conn.getOutputStream().write(reqBody.toString().getBytes());

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_OK);
		
		// Get the authorisation object
		JsonObject auth = Json.createReader(conn.getInputStream()).readObject();
		logger.fine("Authorisation object: " + auth);
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return auth;
	}

	/**
	 * Only builds the JWS body of the POST request
	 */
	private JsonObject buildReqBody(String url) throws SignatureException, InvalidKeyException, 
														NoSuchAlgorithmException {
		FlatJwsObject body = new FlatJwsObject();
		
		// Build JWS header
		body.addAlgHeader(signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addKidHeader(accountUrl);
		
		// Set payload to empty string
		body.setPostAsGet();
		
		return body.finalise(keypair.getPrivate(), signAlgoBCName);
	}
}
