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
	// HTTP-01
	private Http01ChallExecutor http01ChallExecutor;
	private String http01RootDir;
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
	
	public void setHttp01RootDir(String http01RootDir) {
		this.http01RootDir = http01RootDir;
	}
	
	/**
	 * Performs the whole pipeline corresponding to the http-01 challenge
	 * @throws IOException 
	 * @throws MalformedURLException 
	 * @throws SignatureException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void performHttp01() throws MalformedURLException, IOException, InvalidKeyException, 
										NoSuchAlgorithmException, NoSuchProviderException, 
										InvalidAlgorithmParameterException, SignatureException {
		retrieveDirectory();
		retrieveNonce();
		createAccount();
		placeOrder();
		retrieveAuthorisations();
		executeHttp01Challenges();
	}

	/**
	 * Retrieves the directory JSON object containing all the other URLs
	 */
	private void retrieveDirectory() throws MalformedURLException, IOException {
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
	private void retrieveNonce() throws MalformedURLException, IOException {
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
	private void createAccount() throws NoSuchAlgorithmException, NoSuchProviderException, 
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
	private void placeOrder() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, 
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
	private void retrieveAuthorisations() throws InvalidKeyException, SignatureException, 
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
	
	/**
	 * Executes all http-01 challenges
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private void executeHttp01Challenges() throws InvalidKeyException, NoSuchAlgorithmException, 
												NoSuchProviderException, SignatureException, 
												IOException {
		// Execute authorisations
		http01ChallExecutor = new Http01ChallExecutor(authorisations, nextNonce);
		http01ChallExecutor.setCrypto(accountKeypair, EC_CURVE_NAME, EC_SIGN_ALGO_BC_NAME, 
										EC_SIGN_ALGO_ACME_NAME);
		http01ChallExecutor.setAccountUrl(accountUrl);
		http01ChallExecutor.setHttp01RootDir(http01RootDir);
		http01ChallExecutor.executeAllHttp01Challenges();
		
		nextNonce = http01ChallExecutor.getNextNonce();
		
		return;
	}
}
