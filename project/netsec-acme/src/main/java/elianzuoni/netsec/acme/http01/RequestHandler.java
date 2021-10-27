package elianzuoni.netsec.acme.http01;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Logger;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

class RequestHandler implements HttpHandler {
	
	private String rootDir;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.http01.RequestHandler");

	RequestHandler(String rootDir) {
		super();
		this.rootDir = rootDir;
		
		logger.info("Created challenge request handler with root directory " + rootDir);
	}

	public void handle(HttpExchange exchange) throws IOException {
		String method = exchange.getRequestMethod();
		String challengePath;
		byte[] challenge;
		OutputStream responseStream;
		
		// We only accept GET requests on this endpoint
		if(!"GET".equals(method)) {
			logger.severe("Invalid method: " + method);
			handleInvalidMethod(exchange);
			return;
		}
		
		// Read challenge from file
		challengePath = exchange.getRequestURI().getPath();
		challengePath = rootDir + challengePath;
		try {
			challenge = Files.readAllBytes(Paths.get(challengePath));
		}
		catch(FileNotFoundException e) {
			logger.severe("Challenge not found at path " + challengePath);
			handleFileNotFound(exchange);
			return;
		}
		
		// Set content type as application/octet-stream
		Headers responseHeaders = exchange.getResponseHeaders();
		responseHeaders.add("Content-Type", "application/octet-stream");
		// Write challenge onto response (with code "200: OK")
		exchange.sendResponseHeaders(200, challenge.length);
		responseStream = exchange.getResponseBody();
		responseStream.write(challenge);
		responseStream.close();
		
		logger.info("Sent " + challenge.length + "-byte long challenge with response code 200: OK\n" +
					new String(challenge));
		
		return;
	}

	private void handleFileNotFound(HttpExchange exchange) throws IOException {
		// Send response code "404: Not Found" and an empty body
		exchange.sendResponseHeaders(404, -1);
		// No body is to be sent: immediately close the output stream
		exchange.getRequestBody().close();
		
		logger.warning("Sent empty response with code 404: Not Found");
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
