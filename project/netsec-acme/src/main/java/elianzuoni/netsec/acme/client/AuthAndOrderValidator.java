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

class AuthAndOrderValidator {
	
	private static final int MAX_VALIDATION_RETRIES = 10;
	private static final int VALIDATION_SLEEP = 2000;
	private String orderUrl;
	private JsonObject order;
	private String nonce;
	private JwsParams jwsParams;
	private Collection<JsonObject> newAuthorisations;
	private JsonObject newOrder;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AuthorisationsValidator");
	

	AuthAndOrderValidator(String orderUrl, JsonObject order, String nonce, JwsParams jwsParams) {
		super();
		this.orderUrl = orderUrl;
		this.order = order;
		this.nonce = nonce;
		this.newAuthorisations = new LinkedList<JsonObject>();
		this.jwsParams = jwsParams;
	}

	Collection<JsonObject> getNewAuthorisations() {
		return newAuthorisations;
	}

	JsonObject getNewOrder() {
		return newOrder;
	}

	String getNextNonce() {
		return nextNonce;
	}

	/**
	 * Retrieves all authorisation objects by sending a POST-as-GET request to the specified 
	 * endpoints on the server, retrying until they all become VALID.
	 * Then, it retrieves the order object until it becomes READY.
	 */
	void validateAuthorisationsAndOrder() throws Exception {
		// Validate all authorisations
		logger.info("Validating authorisations");
		for(JsonValue authValue : order.get("authorizations").asJsonArray()) {
			String authUrl = ((JsonString)authValue).getString();
			JsonObject auth = validateAuthorisation(authUrl);
			newAuthorisations.add(auth);
		}
		
		// Retry until this order becomes READY
		logger.info("Readying the order");
		newOrder = readyOrder(orderUrl);
		
		return;
	}

	/**
	 * Fetches this authorisation object, specified by the URL, until it becomes valid
	 */
	private JsonObject validateAuthorisation(String authUrl) throws Exception {
		JsonObject auth = null;
		boolean authValid = false;

		// Retry until this authorisation becomes VALID
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
		
		// Return if valid, otherwise fail
		if(!authValid) {
			throw new Exception("Authorisation never transitioned to VALID");
			
		}
		
		return auth;
	}
	
	/**
	 * Fetches this order object, specified by the URL, until it becomes ready
	 */
	private JsonObject readyOrder(String orderUrl) throws Exception {
		JsonObject retrOrder = null;
		boolean orderReady = false;

		// Retry until this authorisation becomes VALID
		for(int retry = 0; retry < MAX_VALIDATION_RETRIES; retry++) {
			// First sleep a bit
			logger.fine("Retry number " + retry + " for order URL: " + orderUrl +
						". Going to first sleep for " + VALIDATION_SLEEP + " milliseconds");
			Thread.sleep(VALIDATION_SLEEP);
			
			// Now send the request
			logger.fine("Just woke up, going to retrieve the order");
			retrOrder = retrieveOrder(orderUrl);
			
			// Shift back the nonce for the next request
			nonce = nextNonce;
			
			// Check if the order is ready
			if("ready".equals(retrOrder.getString("status"))) {
				logger.fine("Order is ready");
				orderReady = true;
				break;
			}
			
			logger.fine("Order is still not ready, retrying");
		}
		
		// Return if ready, otherwise fail
		if(!orderReady) {
			throw new Exception("Order never transitioned to READY");
			
		}
		
		return retrOrder;
	}
	
	/**
	 * Retrieves the authorisation located at the specified URL
	 */
	private JsonObject retrieveAuthorisation(String authUrl) throws Exception {		
		// Connect to the authorisation endpoint of the ACME server
		logger.fine("Connecting to authorisation endpoint at URL " + authUrl);
		HttpsURLConnection conn = AcmeUtils.doPostAsGet(authUrl, nonce, jwsParams);

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
	 * Retrieves the order located at the specified URL
	 */
	private JsonObject retrieveOrder(String orderUrl) throws Exception {		
		// Connect to the order endpoint of the ACME server
		logger.fine("Connecting to order endpoint at URL " + orderUrl);
		HttpsURLConnection conn = AcmeUtils.doPostAsGet(orderUrl, nonce, jwsParams);

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_OK);
		
		// Get the order object
		JsonObject retrOrder = Json.createReader(conn.getInputStream()).readObject();
		logger.fine("Order object: " + retrOrder);
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return retrOrder;
	}
}
