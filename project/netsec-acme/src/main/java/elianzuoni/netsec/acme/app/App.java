package elianzuoni.netsec.acme.app;

import java.io.File;
import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import elianzuoni.netsec.acme.http01.Http01ChallengeServer;

public class App {
	
	private static Http01ChallengeServer http01ChallengeServer;
	private static final int HTTP01_PORT = 5002;
	private static final String HTTP01_ROOT_DIR = "src/main/resources/http01/";
	private static final int MAX_SERVERS_THREADS = 8;
	private static Executor serversExecutor = Executors.newFixedThreadPool(MAX_SERVERS_THREADS);
	private static Semaphore shutdownSemaphore = new Semaphore(0);
	private static Logger logger = Logger.getLogger("app.App");

	public static void main(String[] args) throws SecurityException, IOException, InterruptedException {
		setLoggerProperties();
		
		// Set up all servers
		setUpHttp01();
		logger.info("All servers set up");
		
		// Start all servers
		http01ChallengeServer.start(serversExecutor);
		logger.info("All servers started");
		
		// Infinite wait on shutdown semaphore
		shutdownSemaphore.acquire();
	}

	private static void setLoggerProperties() throws SecurityException, IOException {
		Locale.setDefault(Locale.ENGLISH);
		LogManager.getLogManager().
			readConfiguration(App.class.getResourceAsStream("/logging/logging.properties"));
	}
	
	private static void setUpHttp01() throws IOException {
		// Create root directory for http01 server
		if(!(new File(HTTP01_ROOT_DIR).mkdirs())) {
			String errorString = "Could not create root directory for http01 server";
			logger.severe(errorString);
			throw new IOException(errorString);
		}
		logger.fine("Root directory created for http01 server: " + HTTP01_ROOT_DIR);
		
		// Create (and bind) the server
		http01ChallengeServer = new Http01ChallengeServer(HTTP01_PORT, HTTP01_ROOT_DIR);
		logger.fine("Created http01 server and bound to port " + HTTP01_PORT);
		
		return;
	}
}
