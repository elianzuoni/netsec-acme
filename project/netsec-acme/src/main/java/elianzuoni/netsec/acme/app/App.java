package elianzuoni.netsec.acme.app;

import java.io.File;
import java.security.Security;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import elianzuoni.netsec.acme.client.AcmeClient;
import elianzuoni.netsec.acme.dns.NameServer;
import elianzuoni.netsec.acme.http01.Http01Server;
import elianzuoni.netsec.acme.https.CertServer;
import elianzuoni.netsec.acme.shutdown.ShutdownServer;

public class App {
	
	private static CliParams cli;
	private static Http01Server http01Server;
	private static final int HTTP01_PORT = 5002;
	private static final String HTTP01_ROOT_DIR = "rtresources/http01/";
	private static NameServer dnsServer;
	private static final int DNS_PORT = 10053;
	private static final String DNS01_ROOT_DIR = "rtresources/dns01/";
	private static final String DNS01_TXT_RECORD_FILENAME = "txt_record";
	private static final int HTTPS_PORT = 5001;
	private static final String HTTPS_ROOT_DIR = "rtresources/https/";
	private static final String HTTPS_CERT_FILENAME = "cert_chain.pem";
	private static final String HTTPS_KEYSTORE_FILENAME = "keystore.ks";
	private static final String HTTPS_CERT_KEYSTORE_ALIAS = "berkila";
	private static CertServer certServer;
	private static ShutdownServer shutdownServer;
	private static final int SHUTDOWN_PORT = 5003;
	private static final int MAX_SERVERS_THREADS = 10;
	private static ExecutorService serversExecutor = Executors.newFixedThreadPool(MAX_SERVERS_THREADS);
	private static AcmeClient acmeClient;
	private static Semaphore shutdownSemaphore = new Semaphore(0);
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.app.App");

	
	public enum ChallengeType {
		HTTP_01,
		DNS_01,
	}
	
	public static void main(String[] args) throws Exception {
		// Parse command-line arguments
		cli = CliParams.parse(args);
				
		setLoggerProperties();
		Security.addProvider(new BouncyCastleProvider());
		
		// Set up all servers
		setUpAndCreateHttp01();
		setUpAndCreateDns();
		setUpHttps();
		logger.info("All servers set up");
		
		// Start all servers except HTTPS
		http01Server.start(serversExecutor);
		dnsServer.start(serversExecutor);
		logger.info("All servers started except HTTPS and shutdown");
		
		// Set up client
		acmeClient = new AcmeClient(cli.dir, cli.domains);
		acmeClient.setHttp01RootDir(HTTP01_ROOT_DIR);
		acmeClient.setDns01FileInfo(DNS01_ROOT_DIR, DNS01_TXT_RECORD_FILENAME);
		acmeClient.setHttpsFileInfo(HTTPS_ROOT_DIR, HTTPS_CERT_FILENAME, 
									HTTPS_KEYSTORE_FILENAME, HTTPS_CERT_KEYSTORE_ALIAS);
		
		// Operate client
		acmeClient.fatica(cli.challType);
		
		// Launch HTTPS server
		createHttps();
		certServer.start(serversExecutor);
		logger.info("HTTPS server started");
		
		// Launch shutdown server
		setUpAndCreateShutdown();
		shutdownServer.start(serversExecutor);
		logger.info("Shutdown server started");
		
		// Wait on shutdown semaphore
		shutdownSemaphore.acquire();
		
		// Shut down
		logger.info("Received shutdown command, closing in 5 seconds");
		Thread.sleep(5000);
		System.exit(0);
		
		return;
	}

	private static void setLoggerProperties() throws Exception {
		Locale.setDefault(Locale.ENGLISH);
		LogManager.getLogManager().
			readConfiguration(App.class.getResourceAsStream("/logging/logging.properties"));
	}
	
	private static void setUpAndCreateHttp01() throws Exception {
		// Create root directory for http01 server, if not existent yet
		if (new File(HTTP01_ROOT_DIR).mkdirs()) {
			logger.fine("Root directory created for http01 server: " + HTTP01_ROOT_DIR);
		}
		
		// Create (and bind) the server
		http01Server = new Http01Server(cli.ipAddrForAll, HTTP01_PORT, HTTP01_ROOT_DIR);
		logger.fine("Created http01 server and bound to port " + HTTP01_PORT);
		
		return;
	}
	
	private static void setUpAndCreateDns() throws Exception {
		// Create root directory for dns-01 server, if not existent yet
		if (new File(DNS01_ROOT_DIR).mkdirs()) {
			logger.fine("Root directory created for dns01 server: " + DNS01_ROOT_DIR);
		}
		
		// Create (and bind) the server
		dnsServer = new NameServer(DNS_PORT, cli.ipAddrForAll, DNS01_ROOT_DIR, 
									DNS01_TXT_RECORD_FILENAME);
		logger.fine("Created dns01 server and bound to port " + DNS_PORT);
		
		return;
	}
	
	private static void setUpHttps() throws Exception {
		// Create root directory for https server, if not existent yet
		if (new File(HTTPS_ROOT_DIR).mkdirs()) {
			logger.fine("Root directory created for https server: " + HTTPS_ROOT_DIR);
		}
		
		return;
	}
	
	private static void createHttps() throws Exception {
		// Create (and bind) the server
		certServer = new CertServer(cli.ipAddrForAll, HTTPS_PORT, HTTPS_ROOT_DIR, 
									HTTPS_CERT_FILENAME, HTTPS_KEYSTORE_FILENAME, 
									HTTPS_CERT_KEYSTORE_ALIAS);
		logger.fine("Created https server and bound to port " + HTTPS_PORT);
	}
	
	private static void setUpAndCreateShutdown() throws Exception {
		// Create (and bind) the server
		shutdownServer = new ShutdownServer(cli.ipAddrForAll, SHUTDOWN_PORT, shutdownSemaphore);
		logger.fine("Created shutdown server and bound to port " + SHUTDOWN_PORT);
		
		return;
	}
}
