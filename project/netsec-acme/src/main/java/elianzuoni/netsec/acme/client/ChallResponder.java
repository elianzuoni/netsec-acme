package elianzuoni.netsec.acme.client;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.utils.HttpUtils;

class ChallResponder {

	private String nonce;
	private Collection<String> urls;
	private KeyPair accountKeypair;
	private String signAlgoBCName;
	private String signAlgoAcmeName;
	private String accountUrl;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.ChallResponder");
	
	
	ChallResponder(String nonce, Collection<String> urls) {
		super();
		this.nonce = nonce;
		this.urls = urls;
	}
	
	String getNextNonce() {
		return nextNonce;
	}

	void setAccountUrl(String accountUrl) {
		this.accountUrl = accountUrl;
	}

	void setCrypto(KeyPair keypair, String signAlgoBCName, String signAlgoAcmeName) {
		this.accountKeypair = keypair;
		this.signAlgoBCName = signAlgoBCName;
		this.signAlgoAcmeName = signAlgoAcmeName;
	}
	
	/**
	 * Responds to all challenges at the provided URLs with an empty-body POST request
	 */
	void respondToAllChallenges() throws InvalidKeyException, SignatureException, 
										NoSuchAlgorithmException, MalformedURLException, IOException {
		for(String url : urls) {
			// Send the confirmation
			respondToChallenge(url);
			
			// Shift back the nonce for the next request
			nonce = nextNonce;
		}
		
		return;
	}
	
	/**
	 * Responds to this challenge by sending an empty payload to the URL inside it
	 */
	private void respondToChallenge(String url) throws InvalidKeyException, 
											SignatureException, NoSuchAlgorithmException, 
											MalformedURLException, IOException {
		// Connect to the challenge endpoint of the ACME server
		logger.fine("Connecting to challenge endpoint at URL " + url);
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
		
		// Get the order object
		JsonObject newChall = Json.createReader(conn.getInputStream()).readObject();
		logger.fine("Updated challenge object: " + newChall);
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return;
	}
	
	/**
	 * Only builds the JWS body of the POST request
	 */
	private JsonObject buildReqBody(String url) throws SignatureException, InvalidKeyException, 
															NoSuchAlgorithmException {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addKidHeader(accountUrl);
		
		// Leave JWS payload empty
		
		return body.finalise(accountKeypair.getPrivate(), signAlgoBCName);
	}
}
