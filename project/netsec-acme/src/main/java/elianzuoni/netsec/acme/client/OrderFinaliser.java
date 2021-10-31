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

	/**
	 * Finalises the order by sending the CSR, then waits for the order to be VALID
	 */
	void finaliseOrder() throws Exception {
		// Connect to the newOrder endpoint of the ACME server
		logger.fine("Connecting to finalise endpoint at URL " + finaliseUrl);
		String csr = Csr.generateCsr(certKeypair, domains);
		HttpsURLConnection conn = AcmeUtils.sendRequest(finaliseUrl, nonce, jwsParams, buildReqBody(csr));

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
	 * Only builds the JWS body of the POST request
	 */
	private JsonObject buildReqBody(String csr) throws Exception {
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
}
