package elianzuoni.netsec.acme.client;

import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.csr.Csr;
import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.AcmeUtils;
import elianzuoni.netsec.acme.utils.HttpUtils;

public class OrderFinaliser {
	
	private static final int MAX_VALIDATION_RETRIES = 10;
	private static final int VALIDATION_SLEEP = 2000;
	private String finaliseUrl;
	private Collection<String> domains;
	private String orderUrl;
	private KeyPair certKeypair;
	private String nonce;
	private JwsParams jwsParams;
	private JsonObject newOrder;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.OrderFinaliser");
	
	
	OrderFinaliser(String finaliseUrl, String orderUrl, String nonce, JwsParams jwsParams) {
		super();
		this.finaliseUrl = finaliseUrl;
		this.orderUrl = orderUrl;
		this.nonce = nonce;
		this.jwsParams = jwsParams;
	}

	void setDomains(Collection<String> domains) {
		this.domains = domains;
	}

	void setCertKeypair(KeyPair certKeypair) {
		this.certKeypair = certKeypair;
	}

	JsonObject getNewOrder() {
		return newOrder;
	}

	String getNextNonce() {
		return nextNonce;
	}
	
	void finaliseAndValidateOrder() throws Exception {
		finaliseOrder();
		
		// Shift back the nonce for the next request
		nonce = nextNonce;
		
		newOrder = validateOrder();
		
		return;
	}

	/**
	 * Finalises the order by sending the CSR
	 */
	private void finaliseOrder() throws Exception {
		// Connect to the finalise endpoint of the ACME server
		logger.fine("Connecting to finalise endpoint at URL " + finaliseUrl);
		String csr = Csr.generateCsr(certKeypair, domains);
		HttpsURLConnection conn = AcmeUtils.sendRequest(finaliseUrl, nonce, jwsParams, buildFinaliseReqBody(csr));

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_OK);;
		
		// Get the order object
		newOrder = Json.createReader(conn.getInputStream()).readObject();
		logger.fine("New order object: " + newOrder);
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return;
	}
	
	/**
	 * Validates the order by repeatedly sending POST-as-GET requests until it becomes VALID
	 */
	private JsonObject validateOrder() throws Exception {
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
			if("valid".equals(retrOrder.getString("status"))) {
				logger.fine("Order is valid");
				orderReady = true;
				break;
			}
			
			logger.fine("Order is still not valid, retrying");
		}
		
		// Return if ready, otherwise fail
		if(!orderReady) {
			throw new Exception("Order never transitioned to VALID");
			
		}
		
		return retrOrder;
	}
	
	/**
	 * Only builds the JWS body of the POST request
	 */
	private JsonObject buildFinaliseReqBody(String csr) throws Exception {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(jwsParams.signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(finaliseUrl);
		body.addKidHeader(jwsParams.accountUrl);
		
		// Build JWS payload
		body.addPayloadEntry("csr", Json.createValue(csr));
		
		return body.finalise(jwsParams.accountKeypair.getPrivate(), jwsParams.signAlgoBCName);
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
