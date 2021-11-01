package elianzuoni.netsec.acme.https;

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.concurrent.Executor;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsParameters;

public class CertServer {
	
	private HttpsServer httpsServer;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.https.CertServer");

	public CertServer(String addr, int tcpPort, String rootDir, String certFilename, 
						String keystoreFilename, String keyAlias) throws Exception {
		super();
		
		this.httpsServer = HttpsServer.create(new InetSocketAddress(addr, tcpPort), 0);
		configureHttps(rootDir + keystoreFilename, keyAlias);
		this.httpsServer.createContext("/", new RequestHandler(rootDir, certFilename));
		
		logger.info("Server created and bound to port " + tcpPort + ", rooted on directory " + rootDir);
	}

	public void start(Executor executor) {
		httpsServer.setExecutor(executor);
		httpsServer.start();
		
		logger.info("Server started");
		
		return;
	}
	
	private void configureHttps(String keystoreFilepath, String keyAlias) throws Exception {
		SSLContext sslCtx = SSLContext.getInstance("TLS");
		
		// Load keystore
		logger.fine("Loading keystore " + keystoreFilepath);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(keystoreFilepath), "barf".toCharArray());
		
		// Create key manager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, null);
        
        // Create trust manager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);

        // Configure HTTPS with this SSL context
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        httpsServer.setHttpsConfigurator (new HttpsConfigurator(sslCtx) {
        	public void configure(HttpsParameters params) {
                try {
                    // initialise the SSL context
                    SSLContext context = getSSLContext();
                    SSLEngine engine = context.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());

                    // Set the SSL parameters
                    SSLParameters sslParameters = context.getSupportedSSLParameters();
                    params.setSSLParameters(sslParameters);

                } catch (Exception ex) {
                    System.out.println("Failed to configure HTTPS connection");
                    ex.printStackTrace();
                }
            }
        });
        
        return;
	}
}
