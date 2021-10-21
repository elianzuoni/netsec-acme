package elianzuoni.netsec.acme.jose;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.json.Json;
import javax.json.JsonObject;

public class Jwk {
	
	/**
	 * Returns a JWK representation of the provided EC public key
	 */
	public static JsonObject fromEcPublicKey(ECPublicKey pk, String crv) {		
		// Get the byte-array big-endian representations of the coordinates
		byte xBytes[] = pk.getW().getAffineX().toByteArray();
		byte yBytes[] = pk.getW().getAffineY().toByteArray();
		
		// Create the JSON object (with field names in alphabetical order)
		Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
		JsonObject jwk = Json.createObjectBuilder().
							add("crv", crv).
							add("kty", "EC").
							add("x", base64Encoder.encodeToString(xBytes)).
							add("y", base64Encoder.encodeToString(yBytes)).
							build();
		
		return jwk;
	}
	
	/**
	 * Get the JWK thumbprint of this public key
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static String getThumbprint(ECPublicKey pk, String crv) throws NoSuchAlgorithmException, 
																		NoSuchProviderException {
		// Construct the JWK already in the right format
		JsonObject jwk = fromEcPublicKey(pk, crv);
		byte jwkBytes[] = jwk.toString().getBytes(StandardCharsets.UTF_8);
		
		// Hash it with SHA-256
		MessageDigest digestor = MessageDigest.getInstance("SHA-256", "BC");
		byte hash[] = digestor.digest(jwkBytes);
		
		// Encode the hash
		Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
		String hashEncoded = base64Encoder.encodeToString(hash);
		
		return hashEncoded;
	}
}
