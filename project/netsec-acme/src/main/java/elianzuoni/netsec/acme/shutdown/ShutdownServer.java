package elianzuoni.netsec.acme.shutdown;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;
import java.util.logging.Logger;

import com.sun.net.httpserver.HttpServer;

public class ShutdownServer {
	
	private HttpServer httpServer;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.shutdown.ShutdownServer");

	public ShutdownServer(String addr, int tcpPort, Semaphore shutdownSemaphore) throws IOException {
		super();
		
		this.httpServer = HttpServer.create(new InetSocketAddress(addr, tcpPort), 0);
		this.httpServer.createContext("/", new RequestHandler(shutdownSemaphore));
		
		logger.info("Server created and bound to port " + tcpPort);
	}
	
	public void start(Executor executor) {
		httpServer.setExecutor(executor);
		httpServer.start();
		
		logger.info("Server started");
		
		return;
	}
}
