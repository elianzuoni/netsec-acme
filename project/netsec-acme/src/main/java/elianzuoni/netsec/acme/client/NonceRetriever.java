package elianzuoni.netsec.acme.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

class NonceRetriever {
	private String url;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.NonceRetriever");
	
	NonceRetriever(String url) {
		super();
		this.url = url;
	}

	String getNextNonce() {
		return nextNonce;
	}

	/**
	 * Retrieves the nonce String via a HEAD request over HTTPS.
	 */
	void retrieveNonce() throws MalformedURLException, IOException {
		// Connect to the newNonce endpoint of the ACME server
		logger.fine("Connecting to newNonce endpoint at URL " + url);
		HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
		
		// Set the method to HEAD
		conn.setRequestMethod("HEAD");
		
		// Fire the request
		conn.connect();

		// Check the response code
		AcmeClient.checkResponseCode(conn, logger, HttpURLConnection.HTTP_OK);
		
		// Get the next nonce
		nextNonce = AcmeClient.getRequiredHeader(conn, "Replay-Nonce", logger);
		logger.fine("Next nonce: " + nextNonce);
		
		return;
	}
}
