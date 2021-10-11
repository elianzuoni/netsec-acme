package elianzuoni.netsec.acme.client;

import java.io.IOException;
import java.net.MalformedURLException;

public class AcmeClient {
	
	private String directoryUrl;
	private DirectoryRetriever directoryRetriever;

	public AcmeClient(String directoryUrl) throws MalformedURLException, IOException {
		super();
		this.directoryUrl = directoryUrl;
		
		this.directoryRetriever = new DirectoryRetriever(directoryUrl);
		directoryRetriever.getDirectory();
	}
}
