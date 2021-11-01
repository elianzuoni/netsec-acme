package elianzuoni.netsec.acme.dns;

import java.net.InetAddress;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Record;

class AQueryHandler {
	
	private static final int DEFAULT_RECORD_TTL = 86400;
	private final String ipAddrForAll;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.dns.AQueryHandler");
	
	
	AQueryHandler(String ipAddrForAll) {
		super();
		this.ipAddrForAll = ipAddrForAll;
	}

	public ARecord getAnswer(Record question) {
		logger.info("Got Query:\n" + question + "\nAnswering with address " + ipAddrForAll);
		try {
			return new ARecord(question.getName(), DClass.IN, DEFAULT_RECORD_TTL, 
								InetAddress.getByName(ipAddrForAll));
			/*
			return Record.fromString(Name.root, Type.A, DClass.IN, DEFAULT_RECORD_TTL,
									ipAddrForAll, Name.root);
			*/
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Received exception when building answer Record", e);
		}
		
		return null;
	}
}
