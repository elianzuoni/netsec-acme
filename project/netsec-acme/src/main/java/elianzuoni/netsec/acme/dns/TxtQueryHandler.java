package elianzuoni.netsec.acme.dns;

import java.util.function.UnaryOperator;
import java.util.logging.Logger;

import org.xbill.DNS.Record;

class TxtQueryHandler implements UnaryOperator<Record> {

	private static final int DEFAULT_RECORD_TTL = 86400;
	private final String dns01RootDir;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.dns.TxtQueryHandler");
	
	TxtQueryHandler(String dns01RootDir) {
		super();
		this.dns01RootDir = dns01RootDir;
	}

	@Override
	public Record apply(Record t) {
		// TODO Auto-generated method stub
		return null;
	}

}
