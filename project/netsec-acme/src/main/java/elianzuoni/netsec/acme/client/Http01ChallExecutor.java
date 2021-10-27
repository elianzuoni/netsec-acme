package elianzuoni.netsec.acme.client;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.json.JsonObject;
import javax.json.JsonValue;

import elianzuoni.netsec.acme.jose.Jwk;

class Http01ChallExecutor {
	
	private static final String HTTP01_CHALL_DIR = ".well-known/acme-challenge/";
	private Collection<JsonObject> authorisations;
	private KeyPair accountKeypair;
	private String crv;
	private String http01RootDir;
	private Collection<String> respondUrls;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.Http01ChallExecutor");
	
	Http01ChallExecutor(Collection<JsonObject> authorisations) {
		super();
		this.authorisations = authorisations;
		
		respondUrls = new LinkedList<String>();
	}
	
	Collection<String> getRespondUrls() {
		return respondUrls;
	}

	void setCrypto(KeyPair accountKeypair, String crv) {
		this.accountKeypair = accountKeypair;
		this.crv = crv;
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
		String jwkThumbprint = Jwk.getThumbprint((ECPublicKey)accountKeypair.getPublic(), crv);
		
		// Execute all authorisations
		for(JsonObject auth : authorisations) {
			logger.fine("Executing http01 challenge in authorisation: " + auth);
			
			// Look for the http-01 challenge in this authorisation
			for(JsonValue chall : auth.getJsonArray("challenges")) {
				JsonObject http01Chall = chall.asJsonObject();
				
				if(!"http-01".equals(http01Chall.getString("type"))) {
					continue;
				}
				
				// We've made it to the http-01 challenge
				logger.fine("Executing challenge: " + http01Chall);
				
				// Create the file
				fulfilHttp01Challenge(http01Chall, jwkThumbprint);
				
				// Note down the URL to contact to send the confirmation
				respondUrls.add(http01Chall.getString("url"));
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
		
		// No need to inform our http-01 server
		
		return;
	}
}
