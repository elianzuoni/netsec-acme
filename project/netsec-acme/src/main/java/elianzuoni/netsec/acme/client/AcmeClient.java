package elianzuoni.netsec.acme.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

public class AcmeClient {

	// Keypair and signature
	private static final String EC_CURVE_NAME = "P-256";
	private static final String EC_SIGN_ALGO_ACME_NAME = "ES256";
	private static final String EC_SIGN_ALGO_BC_NAME = "SHA256withPLAIN-ECDSA";
	private KeyPair accountKeypair;
	// Directory
	private DirectoryRetriever directoryRetriever;
	private String directoryUrl;
	private JsonObject directory;
	// Nonce
	private NonceRetriever nonceRetriever;
	private String nextNonce;
	// Account creation
	private AccountCreator accountCreator;
	private String accountUrl;
	// Order placement
	private OrderPlacer orderPlacer;
	private Collection<String> domains;
	private JsonObject order;
	// Authorisations retrieval
	private AuthorisationsRetriever authorisationsRetriever;
	private Collection<JsonObject> authorisations;
	// Logger
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AcmeClient");

	public AcmeClient(String directoryUrl, Collection<String> domains) throws NoSuchAlgorithmException, 
								NoSuchProviderException, InvalidAlgorithmParameterException {
		super();
		this.directoryUrl = directoryUrl;
		this.domains = domains;
		
		// Generate the keypair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
		keyGen.initialize(new ECGenParameterSpec(EC_CURVE_NAME));
		accountKeypair = keyGen.generateKeyPair();
		logger.info("Generated public key:\n" + accountKeypair.getPublic());
	}
	
	/**
	 * Retrieves the directory JSON object containing all the other URLs
	 */
	public void retrieveDirectory() throws MalformedURLException, IOException {
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
	 * response.
	 */
	public void createAccount() throws NoSuchAlgorithmException, NoSuchProviderException, 
										InvalidAlgorithmParameterException, InvalidKeyException, 
										SignatureException, IOException {
		// Create the account
		accountCreator = new AccountCreator(directory.getString("newAccount"), nextNonce);
		accountCreator.setCrypto(accountKeypair, EC_CURVE_NAME, EC_SIGN_ALGO_BC_NAME, 
								EC_SIGN_ALGO_ACME_NAME);
		accountCreator.createAccount();
		
		accountUrl = accountCreator.getAccountUrl();
		nextNonce = accountCreator.getNextNonce();
		
		logger.info("Account created, located at " + accountUrl);
		
		return;
	}
	
	/**
	 * Places an order on the ACME server for the specified domains
	 */
	public void placeOrder() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, 
									NoSuchProviderException, InvalidAlgorithmParameterException, 
									IOException {
		// Place the order
		orderPlacer = new OrderPlacer(directory.getString("newOrder"), nextNonce);
		orderPlacer.setDomains(domains);
		orderPlacer.setCrypto(accountKeypair, EC_SIGN_ALGO_BC_NAME, EC_SIGN_ALGO_ACME_NAME);
		orderPlacer.setAccountUrl(accountUrl);
		orderPlacer.placeOrder();
		
		order = orderPlacer.getOrder();
		nextNonce = orderPlacer.getNextNonce();
		
		logger.info("Order placed: " + order);
		
		return;
	}
	
	/**
	 * Retrieves all the authorisation objects from the URLs specified in the order object
	 */
	public void retrieveAuthorisations() throws InvalidKeyException, SignatureException, 
												NoSuchAlgorithmException, NoSuchProviderException, 
												InvalidAlgorithmParameterException, IOException {
		// Get authorisation URLs
		Collection<String> urls = new LinkedList<String>();
		for(JsonValue auth : order.get("authorizations").asJsonArray()) {
			String authUrl = ((JsonString)auth).getString();
			urls.add(authUrl);
		}
		
		// Retrieve authorisations
		authorisationsRetriever = new AuthorisationsRetriever(urls, nextNonce);
		authorisationsRetriever.setCrypto(accountKeypair, EC_SIGN_ALGO_BC_NAME, EC_SIGN_ALGO_ACME_NAME);
		authorisationsRetriever.setAccountUrl(accountUrl);
		authorisationsRetriever.retrieveAuthorisations();
		
		authorisations = authorisationsRetriever.getAuthorisations();
		nextNonce = authorisationsRetriever.getNextNonce();
		
		logger.info("Retrieved authorisations: " + authorisations);
		
		return;
	}
}
