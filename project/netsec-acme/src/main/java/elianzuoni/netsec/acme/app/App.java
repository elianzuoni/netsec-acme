package elianzuoni.netsec.acme.app;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Locale;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import elianzuoni.netsec.acme.client.AcmeClient;
import elianzuoni.netsec.acme.http01.Http01Server;

public class App {
	
	private static Http01Server http01ChallengeServer;
	private static final int HTTP01_PORT = 5002;
	private static final String HTTP01_ROOT_DIR = "src/main/resources/http01/";
	private static final int MAX_SERVERS_THREADS = 8;
	private static Executor serversExecutor = Executors.newFixedThreadPool(MAX_SERVERS_THREADS);
	private static final String ACME_DIR_URL = "https://localhost:14000/dir";
	private static AcmeClient acmeClient;
	private static Semaphore shutdownSemaphore = new Semaphore(0);
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.app.App");

	public static void main(String[] args) throws SecurityException, IOException, InterruptedException, 
												NoSuchAlgorithmException, NoSuchProviderException, 
												InvalidAlgorithmParameterException, InvalidKeyException, 
												SignatureException {
		setLoggerProperties();
		Security.addProvider(new BouncyCastleProvider());
		
		// Set up all servers
		setUpHttp01();
		logger.info("All servers set up");
		
		// Start all servers
		http01ChallengeServer.start(serversExecutor);
		logger.info("All servers started");
		
		// Set up client
		acmeClient = new AcmeClient(ACME_DIR_URL, Arrays.asList("localhost"));
		
		// Operate client
		acmeClient.retrieveDirectory();
		acmeClient.retrieveNonce();
		acmeClient.createAccount();
		acmeClient.placeOrder();
		acmeClient.retrieveAuthorisations();
		acmeClient.setHttp01RootDir(HTTP01_ROOT_DIR);
		acmeClient.executeHttp01Challenges();
		
		// Infinite wait on shutdown semaphore
		shutdownSemaphore.acquire();
	}

	private static void setLoggerProperties() throws SecurityException, IOException {
		Locale.setDefault(Locale.ENGLISH);
		LogManager.getLogManager().
			readConfiguration(App.class.getResourceAsStream("/logging/logging.properties"));
	}
	
	private static void setUpHttp01() throws IOException {
		// Create root directory for http01 server, if not existent yet
		if (new File(HTTP01_ROOT_DIR).mkdirs()) {
			logger.fine("Root directory created for http01 server: " + HTTP01_ROOT_DIR);
		}
		
		// Create (and bind) the server
		http01ChallengeServer = new Http01Server(HTTP01_PORT, HTTP01_ROOT_DIR);
		logger.fine("Created http01 server and bound to port " + HTTP01_PORT);
		
		return;
	}
}
