package elianzuoni.netsec.acme.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

public class AcmeClient {

	private static final String EC_CURVE_NAME = "P-256";
	private static final String EC_SIGN_ALGO_ACME_NAME = "ES256";
	private static final String EC_SIGN_ALGO_BC_NAME = "SHA256withPLAIN-ECDSA";
	private KeyPair keypair;
	
	private DirectoryRetriever directoryRetriever;
	private String directoryUrl;
	private JsonObject directory;
	
	private NonceRetriever nonceRetriever;
	private String nextNonce;
	
	private AccountCreator accountCreator;
	private String accountUrl;
	
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AcmeClient");

	public AcmeClient(String directoryUrl) throws NoSuchAlgorithmException, NoSuchProviderException, 
													InvalidAlgorithmParameterException {
		super();
		this.directoryUrl = directoryUrl;
		
		// Generate the keypair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
		keyGen.initialize(new ECGenParameterSpec(EC_CURVE_NAME));
		keypair = keyGen.generateKeyPair();
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
		accountCreator.setKeypair(keypair);
		accountCreator.setCrv(EC_CURVE_NAME);
		accountCreator.setSignAlgoAcmeName(EC_SIGN_ALGO_ACME_NAME);
		accountCreator.setSignAlgoBCName(EC_SIGN_ALGO_BC_NAME);
		accountCreator.createAccount();
		
		accountUrl = accountCreator.getAccountUrl();
		nextNonce = accountCreator.getNextNonce();
		
		logger.info("Account created, located at " + accountUrl);
		logger.info("Account created, public key:\n" + keypair.getPublic());
		
		return;
	}
}
