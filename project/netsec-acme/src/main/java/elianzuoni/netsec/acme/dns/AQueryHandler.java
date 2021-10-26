package elianzuoni.netsec.acme.dns;

import java.io.IOException;
import java.util.function.UnaryOperator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

class AQueryHandler implements UnaryOperator<Record> {
	
	private static final int DEFAULT_RECORD_TTL = 86400;
	private final String ipAddrForAll;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.dns.AQueryHandler");
	
	
	AQueryHandler(String ipAddrForAll) {
		super();
		this.ipAddrForAll = ipAddrForAll;
	}

	@Override
	public Record apply(Record question) {
		logger.info("Got Query:\n" + question + "\nAnswering with address " + ipAddrForAll);
		try {
			return Record.fromString(Name.root, Type.A, DClass.IN, DEFAULT_RECORD_TTL,
									ipAddrForAll, Name.root);
		} catch (IOException e) {
			logger.log(Level.SEVERE, "Received exception when building answer Record", e);
		}
		
		return null;
	}
}
