package elianzuoni.netsec.acme.https;

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
	private String certFilename;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.https.RequestHandler");

	RequestHandler(String rootDir, String certFilename) {
		super();
		this.rootDir = rootDir;
		this.certFilename = certFilename;
		
		logger.info("Created challenge request handler with root directory " + rootDir);
	}

	public void handle(HttpExchange exchange) throws IOException {
		String method = exchange.getRequestMethod();
		String certPath;
		byte[] cert;
		OutputStream responseStream;
		
		logger.info("Handling new exchange");
		
		// We only accept GET requests on this endpoint
		if(!"GET".equals(method)) {
			logger.severe("Invalid method: " + method);
			handleInvalidMethod(exchange);
			return;
		}
		
		// Read cert from file
		certPath = rootDir + certFilename;
		try {
			cert = Files.readAllBytes(Paths.get(certPath));
		}
		catch(FileNotFoundException e) {
			logger.severe("Challenge not found at path " + certPath);
			handleFileNotFound(exchange);
			return;
		}
		
		// Set content type as application/pem-certificate-chain
		Headers responseHeaders = exchange.getResponseHeaders();
		responseHeaders.add("Content-Type", "application/pem-certificate-chain");
		
		// Write cert onto response (with code "200: OK")
		exchange.sendResponseHeaders(200, cert.length);
		responseStream = exchange.getResponseBody();
		responseStream.write(cert);
		responseStream.close();
		
		logger.info("Sent " + cert.length + "-byte long cert chain with response code 200: OK\n" +
					new String(cert));
		
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
