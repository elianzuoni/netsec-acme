package elianzuoni.netsec.acme.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

public class AcmeClient {
	
	private DirectoryRetriever directoryRetriever;
	private String directoryUrl;
	private JsonObject directory;
	
	private NonceRetriever nonceRetriever;
	private String nextNonce;
	
	private AccountCreator accountCreator;
	private String accountUrl;
	private KeyPair keypair;
	
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AcmeClient");

	public AcmeClient(String directoryUrl) {
		super();
		this.directoryUrl = directoryUrl;
	}
	
	/**
	 * Retrieves the directory JSON object containing all the other URLs
	 */
	public void retrieveDirectory() throws MalformedURLException, IOException {
		if(directory != null) {
			return;
		}
		
		// Fetch the directory from the ACME server
		directoryRetriever = new DirectoryRetriever(directoryUrl);
		directoryRetriever.retrieveDirectory();
		
		directory = directoryRetriever.getDirectory();
		
		logger.info("Retrieved directory:\n" + directory);
		
		return;
	}
	
	/**
	 * Retrieves a fresh nonce to be used in the next request
	 */
	public void retrieveNonce() throws MalformedURLException, IOException {
		// Fetch the next nonce from the ACME server
		nonceRetriever = new NonceRetriever(directory.getString("newNonce"));
		nonceRetriever.retrieveNonce();
		
		nextNonce = nonceRetriever.getNextNonce();
		
		logger.info("Retrieved nonce: " + nextNonce);
		
		return;
	}
	
	/**
	 * Creates a new account on the ACME server, identified by the URL returned in the 
	 * response, associating a keypair to it.
	 */
	public void createAccount() throws NoSuchAlgorithmException, NoSuchProviderException, 
										InvalidAlgorithmParameterException, InvalidKeyException, 
										SignatureException, IOException {
		if(accountUrl != null && keypair != null) {
			return;
		}
		
		// Create the account
		accountCreator = new AccountCreator(directory.getString("newAccount"), nextNonce);
		accountCreator.setCrv("P-256");
		accountCreator.setSignAlgoAcmeName("ES256");
		accountCreator.setSignAlgoBCName("SHA256withPLAIN-ECDSA");
		accountCreator.createAccount();
		
		accountUrl = accountCreator.getAccountUrl();
		keypair = accountCreator.getKeypair();
		nextNonce = accountCreator.getNextNonce();
		
		logger.info("Account created, located at " + accountUrl);
		logger.info("Account created, public key:\n" + keypair.getPublic());
		
		return;
	}
	
	/**
	 * Checks whether a non-passing response code was returned.
	 * In case not, the whole response is dumped and an exception is thrown.
	 */
	static void checkResponseCode(HttpsURLConnection conn, Logger logger, int...passingCodes) 
			throws IOException {
		// Check if the response code is good
		for(int code : passingCodes) {
			if(code == conn.getResponseCode()) {
				return;
			}
		}
		
		// Log the error
		String errorString = "Did not receive good response code: " + 
								conn.getResponseCode() + " " + conn.getResponseMessage();
		logger.severe(errorString + "\n" +
					  "Response headers:\n" + getResponseHeaders(conn) + "\n" +
					  "Response payload:\n" + getResponsePayload(conn) + "\n");
		
		throw new IOException(errorString);
	}
	
	/**
	 * Extracts a required header from the response, throwing an exception
	 * if it is absent.
	 */
	static String getRequiredHeader(HttpsURLConnection conn, String key, Logger logger) 
									throws IOException {
		String value = conn.getHeaderField(key);
		
		if(value != null) {
			return value;
		}
		
		// Log the error
		String errorString = "No " + key + " field in the response";
		logger.severe(errorString + "\n" +
					  "Response headers:\n" + getResponseHeaders(conn) + "\n" +
					  "Response payload:\n" + getResponsePayload(conn) + "\n");
		
		throw new IOException(errorString);
	}
	
	/**
	 * Extracts the payload from an HTTP response
	 */
	private static String getResponsePayload(HttpsURLConnection conn) throws IOException {
		InputStream respStream;
		
		try {
			respStream = conn.getInputStream();
		}
		catch(Exception e) {}
		finally {
			respStream = conn.getErrorStream();
		}
		
		String respPayload = new BufferedReader(new InputStreamReader(respStream)).
									lines().
									collect(Collectors.joining("\n"));
		
		return respPayload;
	}

	/**
	 * Extracts the headers from an HTTP response
	 */
	private static String getResponseHeaders(HttpsURLConnection conn) {
		String respHeaders = "";
		
		// Accumulate the headers
		for(Map.Entry<String, List<String>> entry : conn.getHeaderFields().entrySet()) {
			respHeaders += entry.getKey() + ": " + entry.getValue() + "\n";
		}
		
		return respHeaders;
	}
}
