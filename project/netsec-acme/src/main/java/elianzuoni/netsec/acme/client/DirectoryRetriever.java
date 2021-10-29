package elianzuoni.netsec.acme.client;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.utils.HttpUtils;

class DirectoryRetriever {
	
	private String url;
	private JsonObject directory;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.DirectoryRetriever");
	
	DirectoryRetriever(String url) {
		super();
		this.url = url;
	}

	JsonObject getDirectory() {
		return directory;
	}

	/**
	 * Retrieves the directory JSON object via a GET request over HTTPS.
	 */
	void retrieveDirectory() throws Exception {
		// Connect to the directory endpoint of the ACME server
		logger.fine("Connecting to directory endpoint at URL " + url);
		HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
		
		// Set the method to GET
		conn.setRequestMethod("GET");
		
		// Fire the request
		conn.connect();

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_OK);
		
		// Create a JSON object out of the payload
		logger.finer("Parsing into JSON object");
		directory = Json.createReader(conn.getInputStream()).readObject();
		
		return;
	}
}
