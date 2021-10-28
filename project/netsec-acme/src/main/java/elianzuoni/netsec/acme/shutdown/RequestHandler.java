package elianzuoni.netsec.acme.shutdown;

import java.io.IOException;
import java.util.concurrent.Semaphore;
import java.util.logging.Logger;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

class RequestHandler implements HttpHandler {
	
	private Semaphore shutdownSemaphore;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.http01.RequestHandler");

	RequestHandler(Semaphore shutdownSemaphore) {
		super();
		this.shutdownSemaphore = shutdownSemaphore;
		
		logger.info("Created request handler");
	}

	public void handle(HttpExchange exchange) throws IOException {
		String method = exchange.getRequestMethod();
		
		// We only accept GET requests on this endpoint
		if(!"GET".equals(method)) {
			logger.severe("Invalid method: " + method);
			handleInvalidMethod(exchange);
			return;
		}
		
		// Shut everything down
		logger.info("Received GET request: " + exchange.getRequestURI().getPath() + ". Releasing lock");
		shutdownSemaphore.release();
		
		return;
	}

	private void handleInvalidMethod(HttpExchange exchange) throws IOException {
		// Send response code "405: Method Not Allowed" and an empty body
		exchange.sendResponseHeaders(405, -1);
		// No body is to be sent: immediately close the output stream
		exchange.getRequestBody().close();
		
		logger.warning("Sent empty response with code 405: Method Not Allowed");
		return;
	}
}
