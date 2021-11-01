package elianzuoni.netsec.acme.dns;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Logger;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import elianzuoni.netsec.acme.utils.UrlUtils;

class TxtQueryHandler {
	private static final int DEFAULT_RECORD_TTL = 86400;
	private final String dns01RootDir;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.dns.TxtQueryHandler");
	
	TxtQueryHandler(String dns01RootDir) {
		super();
		this.dns01RootDir = dns01RootDir;
	}

	public Collection<Record> getAnswers(Record question) throws Exception {
		Collection<Record> answers = new LinkedList<>();
		
		logger.info("Got Query:\n" + question);
		
		// Construct challenges directory
		String identifier = question.getName().toString();
		String reversedIdentifier = UrlUtils.reverseUrlToPath(identifier);
		String challengesDir = dns01RootDir + reversedIdentifier;
		logger.fine("Challenges directory: " + challengesDir);
		
		// List all files
		for(String filename : new File(challengesDir).list()) {
			// List might include directories
			if(!(new File(challengesDir + filename).isFile())) {
				continue;
			}
			
			// Read file
			String challengeFilepath = challengesDir + filename;
			byte challengeBytes[] = Files.readAllBytes(Paths.get(challengeFilepath));
			String challenge = new String(challengeBytes, StandardCharsets.UTF_8);
			answers.add(Record.fromString(Name.root, Type.TXT, DClass.IN, DEFAULT_RECORD_TTL,
											challenge, Name.root));
		}
		
		return answers;
	}

}
