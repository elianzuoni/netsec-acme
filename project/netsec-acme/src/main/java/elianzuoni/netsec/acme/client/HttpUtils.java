package elianzuoni.netsec.acme.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

class HttpUtils {
	
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.client.HttpUtil");
	
	/**
	 * Checks whether a non-passing response code was returned.
	 * In case not, the whole response is dumped and an exception is thrown.
	 */
	static void checkResponseCode(HttpURLConnection conn, int...passingCodes) 
			throws IOException {
		// Check if the response code is good
		for(int code : passingCodes) {
			if(code == conn.getResponseCode()) {
				return;
			}
		}
		
		// Log the error
		String errorString = "Did not receive good response code: " + 
								conn.getResponseCode() + " " + conn.getResponseMessage();
		logger.severe(errorString + "\n" +
					  "Response headers:\n" + getResponseHeaders(conn) + "\n" +
					  "Response payload:\n" + getResponsePayload(conn) + "\n");
		
		throw new IOException(errorString);
	}
	
	/**
	 * Extracts a required header from the response, throwing an exception
	 * if it is absent.
	 */
	static String getRequiredHeader(HttpURLConnection conn, String key) 
									throws IOException {
		String value = conn.getHeaderField(key);
		
		if(value != null) {
			return value;
		}
		
		// Log the error
		String errorString = "No " + key + " field in the response";
		logger.severe(errorString + "\n" +
					  "Response headers:\n" + getResponseHeaders(conn) + "\n" +
					  "Response payload:\n" + getResponsePayload(conn) + "\n");
		
		throw new IOException(errorString);
	}
	
	/**
	 * Extracts the payload from an HTTP response
	 */
	private static String getResponsePayload(HttpURLConnection conn) throws IOException {
		InputStream respStream;
		
		try {
			// Try to get it from the regular stream
			respStream = conn.getInputStream();
		}
		catch(Exception e) {
			// The response bears an error response code
		}
		finally {
			// Get the payload from the error stream
			respStream = conn.getErrorStream();
		}
		
		String respPayload = new BufferedReader(new InputStreamReader(respStream)).
									lines().
									collect(Collectors.joining("\n"));
		
		return respPayload;
	}

	/**
	 * Extracts the headers from an HTTP response
	 */
	private static String getResponseHeaders(HttpURLConnection conn) {
		String respHeaders = "";
		
		// Accumulate the headers
		for(Map.Entry<String, List<String>> entry : conn.getHeaderFields().entrySet()) {
			respHeaders += entry.getKey() + ": " + entry.getValue() + "\n";
		}
		
		return respHeaders;
	}

}
