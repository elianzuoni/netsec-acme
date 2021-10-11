package elianzuoni.netsec.acme.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

class DirectoryRetriever {
	
	private String url;
	private JsonObject directory;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.DirectoryRetriever");
	
	DirectoryRetriever(String url) {
		super();
		this.url = url;
	}

	/**
	 * Lazily retrieves the directory JSON object from the URL specified
	 * in the constructor.
	 */
	JsonObject getDirectory() throws MalformedURLException, IOException {
		if(directory == null){
			logger.info("Retrieving directory at URL " + url);
			retrieveDirectory();
		}
		
		logger.fine("Directory:\n" + directory);
		return directory;
	}

	/**
	 * Retrieves the directory JSON object via a GET request over HTTPS.
	 */
	private void retrieveDirectory() throws MalformedURLException, IOException {
		// Connect to the directory endpoint of the ACME server
		logger.fine("Connecting to directory endpoint at URL " + url);
		HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
		
		// This stream will carry the GET response
		logger.finer("Getting InputStream");
		InputStream respStream = conn.getInputStream();
		
		// Create a JSON object out of it
		logger.finer("Parsing into JSON object");
		directory = Json.createReader(respStream).readObject();
		
		return;
	}
}
