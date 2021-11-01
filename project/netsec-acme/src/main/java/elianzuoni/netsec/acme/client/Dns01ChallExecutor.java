package elianzuoni.netsec.acme.client;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Base64.Encoder;
import java.util.logging.Logger;

import javax.json.JsonObject;
import javax.json.JsonValue;

import elianzuoni.netsec.acme.jose.Jwk;
import elianzuoni.netsec.acme.jose.JwsParams;
import elianzuoni.netsec.acme.utils.UrlUtils;

class Dns01ChallExecutor {
	
	private static final String DNS01_CHALL_DIR = "_acme-challenge/";
	private Collection<JsonObject> authorisations;
	private JwsParams jwsParams;
	private String dns01RootDir;
	private Collection<String> respondUrls;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.Dns01ChallExecutor");
	
	
	Dns01ChallExecutor(Collection<JsonObject> authorisations, JwsParams jwsParams) {
		super();
		this.authorisations = authorisations;
		this.jwsParams = jwsParams;
		
		respondUrls = new LinkedList<String>();
	}
	
	Collection<String> getRespondUrls() {
		return respondUrls;
	}

	void setDns01RootDir(String dns01RootDir) {
		this.dns01RootDir = dns01RootDir;
	}

	/**
	 * Executes the dns01 challenge contained in each authorisation object
	 */
	public void executeAllDns01Challenges() throws Exception {
		// Create the JWK thumbprint
		String jwkThumbprint = Jwk.getThumbprint((ECPublicKey)jwsParams.accountKeypair.getPublic(), 
													jwsParams.crv);
		
		// Execute all authorisations
		for(JsonObject auth : authorisations) {
			logger.fine("Executing dns01 challenge in authorisation: " + auth);
			
			// Get identifier of this authorisation
			String identifier = auth.get("identifier").asJsonObject().getString("value");
			
			// Look for the dns-01 challenge in this authorisation
			for(JsonValue chall : auth.getJsonArray("challenges")) {
				JsonObject dns01Chall = chall.asJsonObject();
				
				if(!"dns-01".equals(dns01Chall.getString("type"))) {
					continue;
				}
				
				// We've made it to the dns-01 challenge
				logger.fine("Executing challenge: " + dns01Chall);
				
				// Create the TXT record
				fulfilDns01Challenge(dns01Chall, identifier, jwkThumbprint);
				
				// Note down the URL to contact to send the confirmation
				respondUrls.add(dns01Chall.getString("url"));
			}
		}
		
		return;
	}

	/**
	 * Fulfils a single challenge by creating the file containing the hashed key authorisation
	 */
	private void fulfilDns01Challenge(JsonObject chall, String identifier, String jwkThumbprint) 
											throws Exception {
		// Construct challenge string
		String challengeString = chall.getString("token") + "." + jwkThumbprint;
		logger.fine("Created dns-01 challenge string " + challengeString);
		
		// Hash it with SHA-256
		MessageDigest digestor = MessageDigest.getInstance("SHA-256", "BC");
		byte hash[] = digestor.digest(challengeString.getBytes(StandardCharsets.UTF_8));
		
		// Encode the hash
		Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
		String hashedChallenge = base64Encoder.encodeToString(hash);
		
		// Construct relative file path by reversing the identifier URL
		String reversedIdentifier = UrlUtils.reverseUrlToPath(identifier);
		
		// Construct file path
		String challengeDir = dns01RootDir + reversedIdentifier + DNS01_CHALL_DIR;
		String challengeFilePath = challengeDir + chall.getString("token");
		
		logger.info("Writing file: " + challengeFilePath);
		
		// Create directories and file, if not yet existent
		new File(challengeDir).mkdirs();
		new File(challengeFilePath).createNewFile();
		
		// Write the challenge onto the file
		FileWriter challengeWriter = new FileWriter(challengeFilePath, false);	// Overwrite file
		challengeWriter.write(hashedChallenge);
		challengeWriter.close();
		
		// No need to inform our dns-01 server
		
		return;
	}
}
