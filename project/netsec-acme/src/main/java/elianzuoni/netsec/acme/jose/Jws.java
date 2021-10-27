package elianzuoni.netsec.acme.jose;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

public class Jws {

	private JsonObjectBuilder headerBuilder;
	private JsonObjectBuilder payloadBuilder;
	private boolean isPostAsGet;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.jose.Jws");
	
	public Jws() {
		super();
		headerBuilder = Json.createObjectBuilder();
		payloadBuilder = Json.createObjectBuilder();
	}
	
	public void setPostAsGet() {
		isPostAsGet = true;
	}
	
	public JsonObject finalise(PrivateKey secretKey, String signAlgo) 
					throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Encoder base64url = Base64.getUrlEncoder().withoutPadding();
		
		// Encode header and payload as base64url without padding
		logger.finer("Encoding header and payload");
		String headerString = headerBuilder.build().toString();
		String headerEncoded = base64url.encodeToString(headerString.getBytes(StandardCharsets.UTF_8));
		// Check if the payload has to be the empty string
		String payloadString = isPostAsGet ? "" : payloadBuilder.build().toString();
		String payloadEncoded = base64url.encodeToString(payloadString.getBytes(StandardCharsets.UTF_8));
		// Build the signing input
		String signingInput = headerEncoded + "." + payloadEncoded;
		
		logger.finer("Encoded header:\n" + headerString);
		logger.finer("Encoded payload:\n" + payloadString);
		
		// Sign
		logger.fine("Signing input: " + signingInput);
		Signature signer = Signature.getInstance(signAlgo);
		signer.initSign(secretKey, new SecureRandom());
		signer.update(signingInput.getBytes());
		byte signature[] = signer.sign();
		logger.fine("Signature is " + signature.length + " bytes long: " + signature.toString());
		String signatureEncoded = base64url.encodeToString(signature);
		
		// Build JWS object
		JsonObject jws = Json.createObjectBuilder().
								add("protected", headerEncoded).
								add("payload", payloadEncoded).
								add("signature", signatureEncoded).
								build();
		logger.finer("Built JWS object:\n" + jws);
		
		return jws;
	}

	public void addHeader(String key, JsonValue value) {
		headerBuilder.add(key, value);
	}
	
	public void addPayloadEntry(String key, JsonValue value) {
		payloadBuilder.add(key, value);
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
	
	public void addJwkHeader(JsonObject jwk) {
		addHeader("jwk", jwk);
	}
	
	public void addKidHeader(String kid) {
		addHeader("kid", Json.createValue(kid));
	}
	
}
