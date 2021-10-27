package elianzuoni.netsec.acme.app;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Locale;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import elianzuoni.netsec.acme.client.AcmeClient;
import elianzuoni.netsec.acme.dns.NameServer;
import elianzuoni.netsec.acme.http01.Http01Server;

public class App {
	
	private static CliParams cli;
	private static Http01Server http01Server;
	private static final int HTTP01_PORT = 5002;
	private static final String HTTP01_ROOT_DIR = "src/main/resources/http01/";
	private static NameServer dnsServer;
	private static final int DNS_PORT = 10053;
	private static final String DNS01_ROOT_DIR = "src/main/resources/dns01/";
	private static final String DNS01_TXT_RECORD_FILENAME = "txt_record";
	private static final int MAX_SERVERS_THREADS = 8;
	private static Executor serversExecutor = Executors.newFixedThreadPool(MAX_SERVERS_THREADS);
	private static AcmeClient acmeClient;
	private static Semaphore shutdownSemaphore = new Semaphore(0);
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.app.App");

	
	public enum ChallengeType {
		HTTP_01,
		DNS_01,
	}
	
	public static void main(String[] args) throws SecurityException, IOException, InterruptedException, 
												NoSuchAlgorithmException, NoSuchProviderException, 
												InvalidAlgorithmParameterException, InvalidKeyException, 
												SignatureException {
		// Parse command-line arguments
		cli = CliParams.parse(args);
				
		setLoggerProperties();
		Security.addProvider(new BouncyCastleProvider());
		
		// Set up all servers
		setUpHttp01();
		setUpDns();
		logger.info("All servers set up");
		
		// Start all servers
		http01Server.start(serversExecutor);
		dnsServer.start(serversExecutor);
		logger.info("All servers started");
		
		// Set up client
		acmeClient = new AcmeClient(cli.dir, cli.domains);
		acmeClient.setHttp01RootDir(HTTP01_ROOT_DIR);
		acmeClient.setDns01RootDir(DNS01_ROOT_DIR);
		acmeClient.setDns01TxtRecordFileName(DNS01_TXT_RECORD_FILENAME);
		
		// Operate client
		acmeClient.fatica(cli.challType, cli.revoke);
		
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
		http01Server = new Http01Server(cli.ipAddrForAll, HTTP01_PORT, HTTP01_ROOT_DIR);
		logger.fine("Created http01 server and bound to port " + HTTP01_PORT);
		
		return;
	}
	
	private static void setUpDns() throws IOException {
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
}
