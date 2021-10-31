package elianzuoni.netsec.acme.https;

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.concurrent.Executor;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

public class CertServer {
	
	private HttpsServer httpsServer;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.https.CertServer");

	public CertServer(String addr, int tcpPort, String rootDir, String certFilename, 
						String keystoreFilename) throws Exception {
		super();
		
		this.httpsServer = HttpsServer.create(new InetSocketAddress(addr, tcpPort), 0);
		this.httpsServer.createContext("/", new RequestHandler(rootDir, certFilename));
		
		configureHttps(rootDir + keystoreFilename);
		
		logger.info("Server created and bound to port " + tcpPort + ", rooted on directory " + rootDir);
	}

	public void start(Executor executor) {
		httpsServer.setExecutor(executor);
		httpsServer.start();
		
		logger.info("Server started");
		
		return;
	}
	
	private void configureHttps(String keystoreFilepath) throws Exception {
		SSLContext sslCtx = SSLContext.getInstance("TLSv1.2");
		
		// Load keystore
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(keystoreFilepath), null);
		
		// Create key manager
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, null);
        KeyManager[] kms = keyManagerFactory.getKeyManagers();
        
        // Set SSL context and HTTPS configurator
        sslCtx.init(kms, null, null);
		httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslCtx));
		
		return;
	}
}
