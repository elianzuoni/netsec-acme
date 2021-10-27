package elianzuoni.netsec.acme.app;

import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Logger;

import elianzuoni.netsec.acme.app.App.ChallengeType;

class CliParams {
	
	private String args[];
	private int argIdx;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.app.CliParams");
	// Decoded parameters
	ChallengeType challType;
	String dir;
	String ipAddrForAll;
	Collection<String> domains;
	boolean revoke;
	
	
	private CliParams(String args[]) {
		this.args = args;
		argIdx = 0;
	}
	
	static CliParams parse(String args[]) {
		CliParams params = new CliParams(args);
		
		params.readPositional();
		params.readKeyword();
		params.checkMandatory();
		
		return params;
	}

	/**
	 * Read positional arguments
	 */
	private void readPositional() {
		// There's only one positional argument
		if("http01".equals(args[argIdx])) {
			logger.fine("Challenge type: http-01");
			challType = ChallengeType.HTTP_01;
		}
		else if("dns01".equals(args[argIdx])) {
			logger.fine("Challenge type: dns-01");
			challType = ChallengeType.DNS_01;
		}
		else {
			throw new IllegalArgumentException("Unknown positional argument: " + args[argIdx]);
		}
		
		argIdx++;
		return;
	}

	/**
	 * Read keyword arguments
	 */
	private void readKeyword() {
		// Iterate over all remaining arguments
		while(argIdx < args.length) {
			String arg = args[argIdx];
			
			if("--dir".equals(arg)) {
				logger.fine("Parsing --dir argument");
				argIdx++;
				readDir();
			}
			else if("--record".equals(arg)) {
				logger.fine("Parsing --record argument");
				argIdx++;
				readIpAddrForAll();
			}
			else if("--domain".equals(arg)) {
				logger.fine("Parsing --domain argument");
				argIdx++;
				readDomain();
			}
			else if("--revoke".equals(arg)) {
				logger.fine("Found --revoke argument");
				revoke = true;
				argIdx++;
			}
			else {
				throw new IllegalArgumentException("Unkown argument: " + arg);
			}
		}
		
		logger.fine("Parsed all keyword arguments");
		
		return;
	}

	/**
	 * Check that all mandatory arguments were supplied
	 */
	private void checkMandatory() {
		if(challType == null) {
			throw new IllegalArgumentException("Argument challType not supplied");
		}
		if(dir == null) {
			throw new IllegalArgumentException("Argument --dir not supplied");
		}
		if(ipAddrForAll == null) {
			throw new IllegalArgumentException("Argument --record not supplied");
		}
		if(domains == null || domains.size() == 0) {
			throw new IllegalArgumentException("Arguments --domain not supplied");
		}
		
		return;
	}

	/**
	 * Read the --dir argument
	 */
	private void readDir() {
		// Check that it wasn't already supplied
		if(dir != null) {
			throw new IllegalArgumentException("Argument --dir already supplied");
		}
		
		// Read and advance
		dir = args[argIdx];
		argIdx++;
		
		return;
	}

	/**
	 * Read the --record argument
	 */
	private void readIpAddrForAll() {
		// Check that it wasn't already supplied
		if(ipAddrForAll != null) {
			throw new IllegalArgumentException("Argument --record already supplied");
		}
		
		// Read and advance
		ipAddrForAll = args[argIdx];
		argIdx++;
		
		return;
	}

	/**
	 * Read a --domain argument
	 */
	private void readDomain() {
		// Accept multiple domains
		
		// Create collection if not existent
		if(domains == null) {
			domains = new LinkedList<String>();
		}
		
		// Read and advance
		domains.add(args[argIdx]);
		argIdx++;
		
		return;
	}
}
