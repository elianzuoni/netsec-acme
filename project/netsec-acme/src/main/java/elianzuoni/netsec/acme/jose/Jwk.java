package elianzuoni.netsec.acme.jose;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;

public class Jwk {
	
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.jose.Jwk");
	
	/**
	 * Returns a JWK representation of the provided EC public key
	 */
	public static JsonObject fromEcPublicKey(ECPublicKey pk, String crv) {		
		// Get the byte-array big-endian representations of the coordinates
		byte xBytes[] = normaliseLength(pk.getW().getAffineX().toByteArray(), 
										pk.getParams().getCurve().getField().getFieldSize());
		byte yBytes[] = normaliseLength(pk.getW().getAffineY().toByteArray(), 
										pk.getParams().getCurve().getField().getFieldSize());
		
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
	
	private static byte[] normaliseLength(byte[] coordRaw, int fieldLenBits) {
		int elemLenBytes = (fieldLenBits + 7)/8;	// Found online, don't really know why
		
		logger.fine("Normalising with respect to target length of coordinate: " + 
						elemLenBytes + " bytes");
		
		if(coordRaw.length == elemLenBytes) {
			logger.fine("Nothing to do, length is already fine");
			return coordRaw;
		}
		
		// Length mismatch: allocate new vector
		byte coordNorm[] = new byte[elemLenBytes];
		
		if(coordRaw.length < elemLenBytes) {
			logger.info("Coordinate byte array too short (" + coordRaw.length +
							" bytes), padding with leading zeros");
			
			// Padding is already there, since new byte array is initialised with zeros
			// Just copy coordRaw at the end of coordNorm
			int delta = elemLenBytes - coordRaw.length;
			for(int i = 0; i < coordRaw.length; i++) {
				coordNorm[delta + i] = coordRaw[i];
			}
		} else {
			logger.info("Coordinate byte array too long(" + coordRaw.length +
							" bytes): trimming leading zeros");
			
			// It must be that the excess length is exactly one, and the first byte is a zero
			int delta = coordRaw.length - elemLenBytes;
			assert(delta == 1);
			assert(coordRaw[0] == (byte)0);
			
			// Copy the end of coordRaw into coordNorm
			for(int i = 0; i < elemLenBytes; i++) {
				coordNorm[i] = coordRaw[delta + i];
			}
		}
		
		return coordNorm;
	}

	/**
	 * Get the JWK thumbprint of this public key
	 */
	public static String getThumbprint(ECPublicKey pk, String crv) throws Exception {
		// Construct the JWK already in the right format
		JsonObject jwk = fromEcPublicKey(pk, crv);
		byte jwkBytes[] = jwk.toString().getBytes(StandardCharsets.UTF_8);
		logger.info("JWK to hash:\n" + jwk);
		
		// Hash it with SHA-256
		MessageDigest digestor = MessageDigest.getInstance("SHA-256", "BC");
		byte hash[] = digestor.digest(jwkBytes);
		
		// Encode the hash
		Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
		String hashEncoded = base64Encoder.encodeToString(hash);
		
		return hashEncoded;
	}
}
