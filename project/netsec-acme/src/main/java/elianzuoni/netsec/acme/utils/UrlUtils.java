package elianzuoni.netsec.acme.utils;

import java.util.logging.Logger;

public class UrlUtils {
	
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.utils.UrlUtils");
	
	public static String reverseUrlToPath(String url) {
		String labels[] = url.split("\\.");
		
		logger.fine("Reversing URL: " + url);
		
		String reversedUrl = "";
		for(String label : labels) {
			reversedUrl = label + "/" + reversedUrl;
		}
		
		logger.fine("Reversed URL: " + reversedUrl);
		
		return reversedUrl;
	}

}
