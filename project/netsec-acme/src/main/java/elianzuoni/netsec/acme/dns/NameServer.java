package elianzuoni.netsec.acme.dns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.concurrent.Executor;
import java.util.function.UnaryOperator;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NameServer {
	
	private static final int MAX_UDP_PAYLOAD_SIZE = 512;
	private final int port;
	private final String ipAddrForAll;
	private final String dns01RootDir;
	private AQueryHandler aQueryHandler;
	private TxtQueryHandler txtQueryHandler;
	private DatagramSocket socket;
	private Executor executor;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.dns.NameServer");
	
	
	public NameServer(int port, String ipAddrForAll, String dns01RootDir) {
		super();
		this.port = port;
		this.ipAddrForAll = ipAddrForAll;
		this.dns01RootDir = dns01RootDir;
		
		aQueryHandler = new AQueryHandler(ipAddrForAll);
		txtQueryHandler = new TxtQueryhandler(dns01RootDir);
	}

	public void setExecutor(Executor executor) {
		this.executor = executor;
	}
	
	/**
	 * Starts listening on a thread determined by the executor
	 */
	public void start() {
		executor.execute(() -> {
			// Make the implicit closure more evident
			try {
				this.listen();
			} catch(Exception e) {
				this.logger.log(Level.SEVERE, "DNS listener caught exception", e);
			}
			
			return;
		});
		
		logger.info("Started listening in a separate thread");
		return;
	}

	/**
	 * Listens for incoming packets
	 */
	private void listen() throws IOException {
		byte rawInPkt[] = new byte[MAX_UDP_PAYLOAD_SIZE];
		DatagramPacket inPkt;
		byte rawOutPkt[];
		DatagramPacket outPkt;
		
		// Open the socket
		socket = new DatagramSocket(port);
		
		while(true) {
			// Allocate packet
			inPkt = new DatagramPacket(rawInPkt, MAX_UDP_PAYLOAD_SIZE);
			
			// Actually listen
			logger.fine("Going to listen for packets");
			socket.receive(inPkt);
			
			// Process the packet
			logger.info("Received packet! Going to process it");
			rawOutPkt = processPacket(rawInPkt);
			
			// Send the response
			logger.info("Going to send response");
			outPkt = new DatagramPacket(rawOutPkt, rawOutPkt.length, 
										inPkt.getAddress(), inPkt.getPort());
			socket.send(outPkt);
		}
	}

	/**
	 * Decode the packet, then dispatch based on what Record Type is in the query
	 */
	private byte[] processPacket(byte[] rawInPkt) {
		Message request = new Message(rawInPkt);
		Record questionRecord;
		Message response = new Message(request.getHeader().getID());
		Record answerRecord;
		
		logger.info("Processing request with ID: " + request.getHeader().getID());
		
		// Repeat the question in the response
		questionRecord = request.getQuestion();
		response.addRecord(questionRecord, Section.QUESTION);
		
		// Select the right handler, based on the request Record Type
		UnaryOperator<Record> handler;
		switch(questionRecord.getType()) 
		{
		case Type.A:
			logger.info("Handling an A query");
			handler = aQueryHandler;
			break;
			
		case Type.TXT:
			logger.info("Handling a TXT Query");
			handler = txtQueryHandler;
			break;
			
		default:
			logger.warning("Handling an unknown-type Query");
			handler = ((message) -> {
				return null;
			});
			break;
		}
		
		// Obtain the answer record
		answerRecord = handler.apply(questionRecord);
		
		// Add it to the response
		response.addRecord(answerRecord, Section.ANSWER);
		
		logger.info("Query handled");
		
		return response.toWire();
	}
}
