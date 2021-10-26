package elianzuoni.netsec.acme.client;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Collection;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jwk;
import elianzuoni.netsec.acme.jose.Jws;

class Http01ChallExecutor {
	
	private static final String HTTP01_CHALL_DIR = ".well-known/acme-challenge/";
	private Collection<JsonObject> authorisations;
	private String nonce;
	private KeyPair keypair;
	private String signAlgoBCName;
	private String signAlgoAcmeName;
	private String crv;
	private String accountUrl;
	private String http01RootDir;
	private String nextNonce;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.Http01ChallExecutor");
	
	Http01ChallExecutor(Collection<JsonObject> authorisations, String nonce) {
		super();
		this.authorisations = authorisations;
		this.nonce = nonce;
	}
	
	String getNextNonce() {
		return nextNonce;
	}

	void setCrypto(KeyPair keypair, String crv, String signAlgoBCName, String signAlgoAcmeName) {
		this.keypair = keypair;
		this.crv = crv;
		this.signAlgoBCName = signAlgoBCName;
		this.signAlgoAcmeName = signAlgoAcmeName;
	}

	void setAccountUrl(String accountUrl) {
		this.accountUrl = accountUrl;
	}

	void setHttp01RootDir(String http01RootDir) {
		this.http01RootDir = http01RootDir;
	}

	/**
	 * Executes the http01 challenge contained in each authorisation object
	 */
	public void executeAllHttp01Challenges() throws NoSuchAlgorithmException, NoSuchProviderException, 
													IOException, InvalidKeyException, 
													SignatureException {
		// Create the JWK thumbprint
		String jwkThumbprint = Jwk.getThumbprint((ECPublicKey)keypair.getPublic(), crv);
		
		for(JsonObject auth : authorisations) {
			logger.fine("Executing http01 challenge in authorisation: " + auth);
			
			// Look for the http-01 challenge in the authorisation
			for(JsonValue chall : auth.getJsonArray("challenges")) {
				JsonObject http01Chall = chall.asJsonObject();
				
				if(!"http-01".equals(http01Chall.getString("type"))) {
					continue;
				}
				
				// We've made it to the http-01 challenge
				logger.fine("Executing challenge: " + http01Chall);
				
				// Create the file
				fulfilHttp01Challenge(http01Chall, jwkThumbprint);
				
				// Send the confirmation
				respondToHttp01Challenge(http01Chall);
				
				// Shift back the nonce for the next request
				nonce = nextNonce;
			}
		}
		
		return;
	}

	/**
	 * Fulfils a single challenge by creating the file containing the key authorisation
	 */
	private void fulfilHttp01Challenge(JsonObject chall, String jwkThumbprint) throws IOException {
		// Construct challenge string
		String challengeString = chall.getString("token") + "." + jwkThumbprint;
		logger.fine("Created http-01 challenge string " + challengeString);
		
		// Construct file path
		String challengeDir = http01RootDir + HTTP01_CHALL_DIR;
		String challengeFilePath = http01RootDir + HTTP01_CHALL_DIR + chall.getString("token");
		
		// Create directories, if not yet existent, and file
		new File(challengeDir).mkdirs();
		new File(challengeFilePath).createNewFile();
		
		// Write the challenge onto the file
		FileWriter challengeWriter = new FileWriter(challengeFilePath);
		challengeWriter.write(challengeString);
		challengeWriter.close();
		
		// No need to inform the web server
		
		return;
	}

	/**
	 * Responds to this challenge by sending an empty payload to the URL inside it
	 * @throws NoSuchAlgorithmException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws MalformedURLException 
	 */
	private void respondToHttp01Challenge(JsonObject chall) throws InvalidKeyException, 
											SignatureException, NoSuchAlgorithmException, 
											MalformedURLException, IOException {
		// Connect to the challenge endpoint of the ACME server
		String url = chall.getString("url");
		logger.fine("Connecting to newOrder endpoint at URL " + url);
		HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
		
		// Set the request to POST and set its headers
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		conn.addRequestProperty("Content-Type", "application/jose+json");
		
		// Build the request body
		JsonObject reqBody = buildReqBody(chall);
		
		// Fire the request
		conn.connect();
		
		// Write the request body
		conn.getOutputStream().write(reqBody.toString().getBytes());

		// Check the response code
		HttpUtils.checkResponseCode(conn, HttpURLConnection.HTTP_OK);
		
		// Get the order object
		JsonObject newChall = Json.createReader(conn.getInputStream()).readObject();
		logger.fine("Updated challenge object: " + newChall);
		
		// Get the next nonce
		nextNonce = HttpUtils.getRequiredHeader(conn, "Replay-Nonce");
		logger.fine("Next nonce: " + nextNonce);
		
		return;
	}
	
	/**
	 * Only builds the JWS body of the POST request
	 */
	private JsonObject buildReqBody(JsonObject chall) throws SignatureException, InvalidKeyException, 
															NoSuchAlgorithmException {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(chall.getString("url"));
		body.addKidHeader(accountUrl);
		
		// Leave JWS payload empty
		
		return body.finalise(keypair.getPrivate(), signAlgoBCName);
	}
}
