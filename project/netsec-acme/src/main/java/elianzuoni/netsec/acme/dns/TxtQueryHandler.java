package elianzuoni.netsec.acme.dns;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.function.UnaryOperator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import elianzuoni.netsec.acme.utils.UrlUtils;

class TxtQueryHandler implements UnaryOperator<Record> {

	private static final int DEFAULT_RECORD_TTL = 86400;
	private final String dns01RootDir;
	private final String txtRecordFileName;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.dns.TxtQueryHandler");
	
	TxtQueryHandler(String dns01RootDir, String txtRecordFileName) {
		super();
		this.dns01RootDir = dns01RootDir;
		this.txtRecordFileName = txtRecordFileName;
	}

	@Override
	public Record apply(Record question) {
		logger.info("Got Query:\n" + question);
		
		// Construct challenge path
		String identifier = question.getName().toString();
		String reversedIdentifier = UrlUtils.reverseUrlToPath(identifier);
		String challengePath = dns01RootDir + reversedIdentifier + txtRecordFileName;
		logger.fine("Challenge path: " + challengePath);
		
		// Read challenge from file
		try {
			byte challengeBytes[] = Files.readAllBytes(Paths.get(challengePath));
			String challenge = new String(challengeBytes, StandardCharsets.UTF_8);
			return Record.fromString(Name.root, Type.TXT, DClass.IN, DEFAULT_RECORD_TTL,
					challenge, Name.root);
		}
		catch(Exception e) {
			logger.log(Level.SEVERE, "Caught exception reading file: ", e);
		}
		
		return null;
	}

}
