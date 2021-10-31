package elianzuoni.netsec.acme.client;

import java.net.HttpURLConnection;
import java.util.Collection;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.AcmeUtils;
import elianzuoni.netsec.acme.utils.HttpUtils;

class OrderPlacer {
	
	private String url;
	private String nonce;
	private Collection<String> domains;
	private JwsParams jwsParams;
	private String orderUrl;
	private JsonObject order;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.OrderPlacer");
	
	/**
	 * @param url the server's endpoint for placing orders
	 * @param nonce the last Replay-Nonce value received
	 */
	OrderPlacer(String url, String nonce, JwsParams jwsParams) {
		super();
		this.url = url;
		this.nonce = nonce;
		this.jwsParams = jwsParams;
	}

	void setDomains(Collection<String> domains) {
		this.domains = domains;
	}
	
	String getOrderUrl() {
		return orderUrl;
	}

	JsonObject getOrder() {
		return order;
	}

	String getNextNonce() {
		return nextNonce;
	}

	/**
	 * Palces a new order by sending a POST request to the specified endpoint on
	 * the server.
	 */
	void placeOrder() throws Exception {		
		// Connect to the newOrder endpoint of the ACME server
		logger.fine("Connecting to newOrder endpoint at URL " + url);
		HttpsURLConnection conn = AcmeUtils.sendRequest(url, nonce, jwsParams, buildReqBody());

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_CREATED);
		
		// Get the order URL
		orderUrl = HttpUtils.getRequiredHeader(conn, "Location");
		logger.fine("Order URL: " + orderUrl);
		
		// Get the order object
		order = Json.createReader(conn.getInputStream()).readObject();
		logger.fine("Order object: " + order);
		
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
		
		// Build JWS payload
		JsonArrayBuilder identifiersBuilder = Json.createArrayBuilder();
		for(String domain : domains) {
			// Add domain to identifiers array
			identifiersBuilder.add(Json.createObjectBuilder().
										add("type", "dns").
										add("value", domain));
		}
		body.addPayloadEntry("identifiers", identifiersBuilder.build());
		
		return body.finalise(jwsParams.accountKeypair.getPrivate(), jwsParams.signAlgoBCName);
	}
}
