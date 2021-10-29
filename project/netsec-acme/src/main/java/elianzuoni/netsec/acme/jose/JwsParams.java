package elianzuoni.netsec.acme.jose;

import java.security.KeyPair;

public class JwsParams {
	
	public final String signAlgoBCName;
	public final String signAlgoAcmeName;
	public final String crv;
	public final KeyPair accountKeypair;
	public String accountUrl;
	
	
	public JwsParams(String signAlgoBCName, String signAlgoAcmeName, String crv, KeyPair accountKeypair) {
		super();
		this.signAlgoBCName = signAlgoBCName;
		this.signAlgoAcmeName = signAlgoAcmeName;
		this.crv = crv;
		this.accountKeypair = accountKeypair;
	}
}
