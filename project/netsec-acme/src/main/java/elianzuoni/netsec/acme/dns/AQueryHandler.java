package elianzuoni.netsec.acme.dns;

import java.util.function.UnaryOperator;
import java.util.logging.Logger;

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
		return Record.fromString(Name.root, Type.A, DClass.IN, DEFAULT_RECORD_TTL,
								ipAddrForAll, Name.root);
	}

}
