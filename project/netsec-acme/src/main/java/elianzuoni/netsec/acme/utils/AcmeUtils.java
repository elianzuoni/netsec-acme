package elianzuoni.netsec.acme.utils;

import java.net.URL;

import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;

import elianzuoni.netsec.acme.jose.Jws;
import elianzuoni.netsec.acme.jose.JwsParams;

public class AcmeUtils {
	
	/**
	 * Sends a POST-as-GET request
	 */
	public static HttpsURLConnection doPostAsGet(String url, String nonce, JwsParams jwsParams) 
			throws Exception {
		return sendRequest(url, nonce, jwsParams, buildPostAsGetReqBody(url, nonce, jwsParams));
	}
	
	/**
	 * Sends an empty POST request
	 */
	public static HttpsURLConnection doEmptyPost(String url, String nonce, JwsParams jwsParams) 
			throws Exception {
		return sendRequest(url, nonce, jwsParams, buildEmptyPostReqBody(url, nonce, jwsParams));
	}
	
	/**
	 * Sends a request to the given URL with the given body
	 */
	public static HttpsURLConnection sendRequest(String url, String nonce, JwsParams jwsParams, 
													JsonObject reqBody) throws Exception {
		HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
		
		// Set the request to POST and set its headers
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		conn.addRequestProperty("Content-Type", "application/jose+json");
		
		// Fire the request
		conn.connect();
		
		// Write the request body
		conn.getOutputStream().write(reqBody.toString().getBytes());
		
		return conn;
	}
	
	/**
	 * Only builds the JWS body of the POST-as-GET request
	 */
	private static JsonObject buildPostAsGetReqBody(String url, String nonce, JwsParams jwsParams) 
									throws Exception {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(jwsParams.signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addKidHeader(jwsParams.accountUrl);
		
		// Set payload to empty string
		body.setPostAsGet();
		
		return body.finalise(jwsParams.accountKeypair.getPrivate(), jwsParams.signAlgoBCName);
	}

	/**
	 * Only builds the JWS body of the empty POST request
	 */
	private static JsonObject buildEmptyPostReqBody(String url, String nonce, JwsParams jwsParams) 
									throws Exception {
		Jws body = new Jws();
		
		// Build JWS header
		body.addAlgHeader(jwsParams.signAlgoAcmeName);
		body.addNonceHeader(nonce);
		body.addUrlHeader(url);
		body.addKidHeader(jwsParams.accountUrl);
		
		// Leave JWS payload empty
		
		return body.finalise(jwsParams.accountKeypair.getPrivate(), jwsParams.signAlgoBCName);
	}
}
