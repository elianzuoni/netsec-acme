package elianzuoni.netsec.acme.dns;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Collection;
import java.util.concurrent.Executor;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class NameServer {
	
	private static final int MAX_UDP_PAYLOAD_SIZE = 512;
	private final int port;
	private AQueryHandler aQueryHandler;
	private TxtQueryHandler txtQueryHandler;
	private DatagramSocket socket;
	private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.dns.NameServer");
	
	
	public NameServer(int port, String ipAddrForAll, String dns01RootDir) {
		super();
		this.port = port;
		
		aQueryHandler = new AQueryHandler(ipAddrForAll);
		txtQueryHandler = new TxtQueryHandler(dns01RootDir);
	}
	
	/**
	 * Starts listening on a thread determined by the executor
	 */
	public void start(Executor executor) {
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
	private void listen() throws Exception {
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
	private byte[] processPacket(byte[] rawInPkt) throws Exception {
		Message request = new Message(rawInPkt);
		Record questionRecord;
		Message response = new Message(request.getHeader().getID());
		
		logger.info("Processing request with ID: " + request.getHeader().getID());
		
		// Set flags in response
		response.getHeader().setFlag(Flags.AA);
	    response.getHeader().setFlag(Flags.QR);
		
		// Repeat the question in the response
		questionRecord = request.getQuestion();
		response.addRecord(questionRecord, Section.QUESTION);
		
		// Select the right handler, based on the request Record Type
		logger.fine("Selecting the handler for record:\n" + questionRecord);
		switch(questionRecord.getType()) 
		{
		case Type.A:
		case Type.AAAA:
			logger.info("Handling an A or AAAA query");
			
			// Get answer record
			Record answerRecord = aQueryHandler.getAnswer(questionRecord);
			// Add it to the response
			response.addRecord(answerRecord, Section.ANSWER);
			
			break;
			
		case Type.TXT:
			logger.info("Handling a TXT Query");
			
			// Get answer records
			Collection<Record> answerRecords = txtQueryHandler.getAnswers(questionRecord);
			// Add them to the response
			for(Record record : answerRecords) {
				response.addRecord(record, Section.ANSWER);
			}
			
			break;
			
		default:
			logger.warning("Handling an unknown-type Query: " + questionRecord.getType());
			return null;
		}
		
		logger.info("Query handled");
		
		return response.toWire();
	}
}
