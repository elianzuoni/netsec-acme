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
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.utils.HttpUtils;

class OrderPlacer {
	
	private String url;
	private String nonce;
	private Collection<String> domains;
	private String signAlgoBCName;
	private String signAlgoAcmeName;
	private KeyPair keypair;
	private String accountUrl;
	private JsonObject order;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.OrderPlacer");
	
	/**
	 * @param url the server's endpoint for placing orders
	 * @param nonce the last Replay-Nonce value received
	 */
	OrderPlacer(String url, String nonce) {
		super();
		this.url = url;
		this.nonce = nonce;
	}

	void setDomains(Collection<String> domains) {
		this.domains = domains;
	}
	
	void setCrypto(KeyPair keypair, String signAlgoBCName, String signAlgoAcmeName) {
		this.keypair = keypair;
		this.signAlgoBCName = signAlgoBCName;
		this.signAlgoAcmeName = signAlgoAcmeName;
	}

	void setAccountUrl(String accountUrl) {
		this.accountUrl = accountUrl;
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
	void placeOrder() throws IOException, InvalidKeyException, SignatureException, 
								NoSuchAlgorithmException, NoSuchProviderException, 
								InvalidAlgorithmParameterException {		
		// Connect to the newOrder endpoint of the ACME server
		logger.fine("Connecting to newOrder endpoint at URL " + url);
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
	private JsonObject buildReqBody() throws SignatureException, InvalidKeyException, 
											NoSuchAlgorithmException {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addKidHeader(accountUrl);
		
		// Build JWS payload
		JsonArrayBuilder identifiersBuilder = Json.createArrayBuilder();
		for(String domain : domains) {
			// Add domain to identifiers array
			identifiersBuilder.add(Json.createObjectBuilder().
										add("type", "dns").
										add("value", domain));
		}
		body.addPayloadEntry("identifiers", identifiersBuilder.build());
		
		return body.finalise(keypair.getPrivate(), signAlgoBCName);
	}
}
