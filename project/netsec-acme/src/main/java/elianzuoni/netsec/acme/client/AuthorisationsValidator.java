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
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.utils.HttpUtils;

class AuthorisationsValidator {
	
	private static final int MAX_VALIDATION_RETRIES = 10;
	private static final int VALIDATION_SLEEP = 5000;
	private JsonObject order;
	private String nonce;
	private String signAlgoBCName;
	private String signAlgoAcmeName;
	private KeyPair keypair;
	private String accountUrl;
	private Collection<JsonObject> authorisations;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AuthorisationsValidator");
	

	AuthorisationsValidator(JsonObject order, String nonce) {
		super();
		this.order = order;
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
	 * endpoints on the server, retrying until they all become VALID
	 */
	void validateAuthorisations() throws Exception {
		// Populate the authorisation collection
		for(JsonValue authValue : order.get("authorizations").asJsonArray()) {
			String authUrl = ((JsonString)authValue).getString();
			
			// Retry until this authorisation becomes VALID
			JsonObject auth = null;
			boolean authValid = false;
			for(int retry = 0; retry < MAX_VALIDATION_RETRIES; retry++) {
				// First sleep a bit
				logger.fine("Retry number " + retry + " for authorisation URL: " + authUrl +
							". Going to first sleep for " + VALIDATION_SLEEP + " milliseconds");
				Thread.sleep(VALIDATION_SLEEP);
				
				// Now send the request
				logger.fine("Just woke up, going to retrieve the authorisation");
				auth = retrieveAuthorisation(authUrl);
				
				// Shift back the nonce for the next request
				nonce = nextNonce;
				
				// Check if the authorisation is valid
				if("valid".equals(auth.getString("status"))) {
					logger.fine("Authorisation is valid");
					authValid = true;
					break;
				}
				
				logger.fine("Authorisation is still not valid, retrying");
			}
			
			// Add if valid, otherwise fail
			if(!authValid) {
				throw new Exception("Authorisation " + auth.getString("url") + 
									" never transitioned to VALID");
				
			}
			authorisations.add(auth);
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
	 * Only builds the JWS body of the POST-as-GET request
	 */
	private JsonObject buildReqBody(String url) throws SignatureException, InvalidKeyException, 
														NoSuchAlgorithmException {
		Jws body = new Jws();
		
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
