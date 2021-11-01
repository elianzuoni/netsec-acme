package elianzuoni.netsec.acme.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Collection;
import java.util.logging.Logger;

import javax.json.JsonObject;

import elianzuoni.netsec.acme.app.App.ChallengeType;
import elianzuoni.netsec.acme.jose.JwsParams;

public class AcmeClient {

	// Keypair and signature
	private static final String EC_CURVE_NAME = "P-256";
	private static final String EC_SIGN_ALGO_ACME_NAME = "ES256";
	private static final String EC_SIGN_ALGO_BC_NAME = "SHA256withPLAIN-ECDSA";
	private KeyPair accountKeypair;
	private JwsParams jwsParams;
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
	private String orderUrl;
	private JsonObject order;
	// Authorisations retrieval
	private AuthRetriever authRetriever;
	private Collection<JsonObject> authorisations;
	// HTTP-01
	private Http01ChallExecutor http01ChallExecutor;
	private String http01RootDir;
	// DNS-01
	private Dns01ChallExecutor dns01ChallExecutor;
	private String dns01RootDir;
	private String dns01TxtRecordFileName;
	// Challenge responding
	private ChallResponder challResponder;
	private Collection<String> challRespondUrls;
	// Authorisations validation
	private AuthAndOrderValidator authAndOrderValidator;
	// CSR
	private OrderFinaliser orderFinaliser;
	KeyPair certKeypair;
	// Certificate download
	private CertificateDownloader certificateDownloader;
	private String httpsRootDir;
	private String certFilename;
	private String keystoreFilename;
	private String keystorePassword;
	// Certificate revocation
	private CertificateRevoker certRevoker;
	// Logger
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.AcmeClient");

	
	public AcmeClient(String directoryUrl, Collection<String> domains) throws Exception {
		super();
		this.directoryUrl = directoryUrl;
		this.domains = domains;
		
		// Generate the keypair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
		keyGen.initialize(new ECGenParameterSpec(EC_CURVE_NAME));
		accountKeypair = keyGen.generateKeyPair();
		logger.info("Generated account public key:\n" + accountKeypair.getPublic());
		certKeypair = keyGen.generateKeyPair();
		logger.info("Generated certificate public key:\n" + certKeypair.getPublic());
		
		// Set JWS parameters
		jwsParams = new JwsParams(EC_SIGN_ALGO_BC_NAME, EC_SIGN_ALGO_ACME_NAME,
									EC_CURVE_NAME, accountKeypair);
	}
	
	public void setHttp01RootDir(String http01RootDir) {
		this.http01RootDir = http01RootDir;
	}
	
	public void setDns01FileInfo(String dns01RootDir, String dns01TxtRecordFileName) {
		this.dns01RootDir = dns01RootDir;
		this.dns01TxtRecordFileName = dns01TxtRecordFileName;
	}

	public void setHttpsFileInfo(String httpsRootDir, String certFilename, 
							String keystoreFilename, String keystorePassword) {
		this.httpsRootDir = httpsRootDir;
		this.certFilename = certFilename;
		this.keystoreFilename = keystoreFilename;
		this.keystorePassword = keystorePassword;
	}
	
	/**
	 * Performs the whole pipeline
	 */
	public void fatica(ChallengeType challType, boolean revoke) throws Exception {
		retrieveDirectory();
		retrieveNonce();
		createAccount();
		placeOrder();
		retrieveAuthorisations();
		if(challType == ChallengeType.HTTP_01) {
			executeHttp01Challenges();
		} else {
			executeDns01Challenges();
		}
		respondToChallenges();
		validateAuthorisationsAndOrder();
		finaliseOrder();
		downloadCertificate();
		if(revoke) {
			revokeCertificate();
		}
	}

	/**
	 * Retrieves the directory JSON object containing all the other URLs
	 */
	private void retrieveDirectory() throws Exception {
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
	private void retrieveNonce() throws Exception {
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
	private void createAccount() throws Exception {
		// Create the account
		accountCreator = new AccountCreator(directory.getString("newAccount"), nextNonce, jwsParams);
		accountCreator.createAccount();
		
		accountUrl = accountCreator.getAccountUrl();
		nextNonce = accountCreator.getNextNonce();
		
		// Update JWS parameters
		jwsParams.accountUrl = accountUrl;
		
		logger.info("Account created, located at " + accountUrl);
		
		return;
	}
	
	/**
	 * Places an order on the ACME server for the specified domains
	 */
	private void placeOrder() throws Exception {
		// Place the order
		orderPlacer = new OrderPlacer(directory.getString("newOrder"), nextNonce, jwsParams);
		orderPlacer.setDomains(domains);
		orderPlacer.placeOrder();
		
		orderUrl = orderPlacer.getOrderUrl();
		order = orderPlacer.getOrder();
		nextNonce = orderPlacer.getNextNonce();
		
		logger.info("Order placed: " + order);
		
		return;
	}
	
	/**
	 * Retrieves all the authorisation objects from the URLs specified in the order object
	 */
	private void retrieveAuthorisations() throws Exception {
		// Retrieve authorisations
		authRetriever = new AuthRetriever(order, nextNonce, jwsParams);
		authRetriever.retrieveAuthorisations();
		
		authorisations = authRetriever.getAuthorisations();
		nextNonce = authRetriever.getNextNonce();
		
		logger.info("Retrieved authorisations: " + authorisations);
		
		return;
	}
	
	/**
	 * Executes all http-01 challenges
	 */
	private void executeHttp01Challenges() throws Exception {
		// Execute authorisations
		http01ChallExecutor = new Http01ChallExecutor(authorisations, jwsParams);
		http01ChallExecutor.setHttp01RootDir(http01RootDir);
		http01ChallExecutor.executeAllHttp01Challenges();
		
		challRespondUrls = http01ChallExecutor.getRespondUrls();
		
		return;
	}
	
	/**
	 * Executes all dns-01 challenges
	 */
	private void executeDns01Challenges() throws Exception {
		// Execute authorisations
		dns01ChallExecutor = new Dns01ChallExecutor(authorisations, jwsParams);
		dns01ChallExecutor.setDns01RootDir(dns01RootDir);
		dns01ChallExecutor.setTxtRecordFileName(dns01TxtRecordFileName);
		dns01ChallExecutor.executeAllDns01Challenges();
		
		challRespondUrls = dns01ChallExecutor.getRespondUrls();
		
		return;
	}
	
	/**
	 * Respond to all challenges, confirming that they are ready
	 */
	private void respondToChallenges() throws Exception {
		// Respond to challenges
		challResponder = new ChallResponder(nextNonce, challRespondUrls, jwsParams);
		challResponder.respondToAllChallenges();
		
		nextNonce = challResponder.getNextNonce();
		
		return;
	}
	
	/**
	 * Validates all the authorisation objects from the URLs specified in the order object
	 * and readies the order.
	 */
	private void validateAuthorisationsAndOrder() throws Exception {
		// Validate authorisations
		authAndOrderValidator = new AuthAndOrderValidator(orderUrl, order, nextNonce, jwsParams);
		authAndOrderValidator.validateAuthorisationsAndOrder();
		
		authorisations = authAndOrderValidator.getNewAuthorisations();
		order = authAndOrderValidator.getNewOrder();
		nextNonce = authAndOrderValidator.getNextNonce();
		
		logger.info("Validated authorisations: " + authorisations);
		logger.info("Readied order: " + order);
		
		return;
	}
	
	/**
	 * Finalises the order and waits for it to be VALID.
	 */
	private void finaliseOrder() throws Exception {
		// Finalise order
		orderFinaliser = new OrderFinaliser(order.getString("finalize"), orderUrl, nextNonce, jwsParams);
		orderFinaliser.setDomains(domains);
		orderFinaliser.setCertKeypair(certKeypair);
		orderFinaliser.finaliseAndValidateOrder();
		
		order = orderFinaliser.getNewOrder();
		nextNonce = orderFinaliser.getNextNonce();
		
		logger.info("Finalised order");
		
		return;
	}
	
	/**
	 * Downloads the certificate into the keystore file
	 */
	private void downloadCertificate() throws Exception {
		// Download certificate
		certificateDownloader = new CertificateDownloader(order.getString("certificate"), 
															nextNonce, jwsParams);
		certificateDownloader.setCertKeypair(certKeypair);
		certificateDownloader.setHttpsRootDir(httpsRootDir);
		certificateDownloader.setCertFilename(certFilename);
		certificateDownloader.setKeystoreFilename(keystoreFilename);
		certificateDownloader.setKeystorePassword(keystorePassword);
		certificateDownloader.downloadCertificate();
		
		nextNonce = certificateDownloader.getNextNonce();
		
		logger.info("Downloaded certificate");
		
		return;
	}
	
	/**
	 * Revokes the certificate
	 */
	private void revokeCertificate() throws Exception {
		// Revoke certificate
		certRevoker = new CertificateRevoker(directory.getString("revokeCert"), 
															nextNonce, jwsParams);
		certRevoker.setKeystoreInfo(httpsRootDir + keystoreFilename, keystorePassword);
		certRevoker.revokeCertificate();
		
		nextNonce = certRevoker.getNextNonce();
		
		logger.info("Revoked certificate");
		
		return;
	}
}
