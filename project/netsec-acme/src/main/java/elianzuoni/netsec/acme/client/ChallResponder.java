package elianzuoni.netsec.acme.client;

import java.net.HttpURLConnection;
import java.util.Collection;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.AcmeUtils;
import elianzuoni.netsec.acme.utils.HttpUtils;

class ChallResponder {

	private String nonce;
	private Collection<String> urls;
	private JwsParams jwsParams;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.ChallResponder");
	
	
	ChallResponder(String nonce, Collection<String> urls, JwsParams jwsParams) {
		super();
		this.nonce = nonce;
		this.urls = urls;
		this.jwsParams = jwsParams;
	}
	
	String getNextNonce() {
		return nextNonce;
	}
	
	/**
	 * Responds to all challenges at the provided URLs with an empty-body POST request
	 */
	void respondToAllChallenges() throws Exception {
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
	private void respondToChallenge(String url) throws Exception {
		// Connect to the challenge endpoint of the ACME server
		logger.fine("Connecting to challenge endpoint at URL " + url);
		HttpsURLConnection conn = AcmeUtils.doEmptyPost(url, nonce, jwsParams);

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
}
