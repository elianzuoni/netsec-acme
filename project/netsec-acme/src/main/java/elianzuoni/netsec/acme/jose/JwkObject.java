package elianzuoni.netsec.acme.jose;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;

public class JwkObject {
	
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.jose.JwkObject");
	
	/**
	 * Returns a JWK representation of the provided EC public key
	 */
	public static JsonObject encodeEcPublicKey(ECPublicKey pk, String crv) {		
		// Get the byte-array big-endian representations of the coordinates
		byte xBytes[] = pk.getW().getAffineX().toByteArray();
		byte yBytes[] = pk.getW().getAffineY().toByteArray();
		
		// Create the JSON object
		Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
		JsonObject jwk = Json.createObjectBuilder().
							add("kty", "EC").
							add("crv", crv).
							add("x", base64Encoder.encodeToString(xBytes)).
							add("y", base64Encoder.encodeToString(yBytes)).
							build();
		
		return jwk;
	}
}
