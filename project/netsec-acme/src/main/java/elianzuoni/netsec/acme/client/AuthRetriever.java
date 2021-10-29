package elianzuoni.netsec.acme.client;

import java.net.HttpURLConnection;
import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.AcmeUtils;
import elianzuoni.netsec.acme.utils.HttpUtils;

class AuthRetriever {
	
	private JsonObject order;
	private String nonce;
	private JwsParams jwsParams;
	private Collection<JsonObject> authorisations;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AuthorisationsRetriever");
	
	
	AuthRetriever(JsonObject order, String nonce, JwsParams jwsParams) {
		super();
		this.order = order;
		this.nonce = nonce;
		this.jwsParams = jwsParams;
		this.authorisations = new LinkedList<JsonObject>();
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
	void retrieveAuthorisations() throws Exception {
		// Populate the authorisation collection
		for(JsonValue auth : order.get("authorizations").asJsonArray()) {
			String authUrl = ((JsonString)auth).getString();
			authorisations.add(retrieveAuthorisation(authUrl));
			
			// Shift back the nonce for the next request
			nonce = nextNonce;
		}
		
		return;
	}
	
	/**
	 * Retrieves the authorisation located at the specified URL
	 */
	private JsonObject retrieveAuthorisation(String url) throws Exception {		
		// Connect to the authorisation endpoint of the ACME server
		logger.fine("Connecting to authorisation endpoint at URL " + url);
		HttpsURLConnection conn = AcmeUtils.doPostAsGet(url, nonce, jwsParams);

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
}
