package elianzuoni.netsec.acme.http01;

import java.net.InetSocketAddress;
import java.util.concurrent.Executor;
import java.util.logging.Logger;

import com.sun.net.httpserver.HttpServer;

public class Http01Server {
	
	private HttpServer httpServer;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.http01.Http01Server");

	public Http01Server(String addr, int tcpPort, String rootDir) throws Exception {
		super();
		
		this.httpServer = HttpServer.create(new InetSocketAddress(addr, tcpPort), 0);
		this.httpServer.createContext("/", new RequestHandler(rootDir));
		
		logger.info("Server created and bound to port " + tcpPort + ", rooted on directory " + rootDir);
	}
	
	public void start(Executor executor) {
		httpServer.setExecutor(executor);
		httpServer.start();
		
		logger.info("Server started");
		
		return;
	}
}
