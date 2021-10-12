package elianzuoni.netsec.acme.jws;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonValue;

public class FlatJwsObject {

	private JsonObject header;
	private JsonObject payload;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.jws.FlatJwsObject");
	
	public FlatJwsObject() {
		super();
		header = Json.createObjectBuilder().build();
		payload = Json.createObjectBuilder().build();
	}
	
	public JsonObject finalise(PrivateKey secretKey) 
					throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		// Encode header and payload as base64url
		logger.finer("Encoding header and payload");
		String headerString = header.toString();
		String headerEncoded = Base64.getUrlEncoder().encodeToString(headerString.getBytes());
		String payloadString = payload.toString();
		String payloadEncoded = Base64.getUrlEncoder().encodeToString(payloadString.getBytes());
		String signingInput = headerEncoded + "." + payloadEncoded;
		
		// Sign
		logger.fine("Signing");
		Signature signer = Signature.getInstance(secretKey.getAlgorithm());
		signer.initSign(secretKey, new SecureRandom());
		signer.update(signingInput.getBytes());
		byte signature[] = signer.sign();
		String signatureEncoded = Base64.getUrlEncoder().encodeToString(signature);
		
		// Build JWS object
		logger.finer("Building JWS object");
		JsonObject jws = Json.createObjectBuilder().
								add("protected", headerEncoded).
								add("payload", payloadEncoded).
								add("signature", signatureEncoded).
								build();
		
		return jws;
	}

	public void addHeader(String key, JsonValue value) {
		header.put(key, value);
	}
	
	public void addPayloadEntry(String key, JsonValue value) {
		payload.put(key, value);
	}
	
	public void addAlgHeader(String alg) {
		addHeader("alg", Json.createValue(alg));
	}
	
	public void addNonceHeader(String nonce) {
		addHeader("nonce", Json.createValue(nonce));
	}
	
	public void addUrlHeader(String url) {
		addHeader("url", Json.createValue(url));
	}
}
