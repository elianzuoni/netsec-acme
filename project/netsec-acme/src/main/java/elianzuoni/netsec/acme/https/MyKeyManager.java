package elianzuoni.netsec.acme.https;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.net.ssl.X509KeyManager;

class  MyKeyManager implements X509KeyManager {
    private X509KeyManager delegate;
    private String keyAlias;
    private Logger logger = Logger.getLogger("elianzuoni.netsec.acme.https.MyKeyManager");

    
    MyKeyManager(X509KeyManager delegate, String keyAlias) {
        this.delegate = delegate;
        this.keyAlias = keyAlias;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    	String clientAlias = delegate.chooseClientAlias(keyType, issuers, socket);
    	logger.info("Called chooseClientAlias, delegate returned: " + clientAlias);
        return clientAlias;
    }

    /**
     * The only override that's not delegated
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    	String serverAlias = delegate.chooseServerAlias(keyType, issuers, socket);
    	logger.info("Called chooseServerAlias, delegate would return: " + serverAlias + 
    			"\nInstead returning: " + keyAlias);
        return keyAlias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
    	X509Certificate chain[] = delegate.getCertificateChain(alias);
    	logger.info("Called chooseServerAlias with alias " + alias + 
    				", delegate returned " + chain.length + " certificates");    	
        return chain;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
    	String serverAliases[] = delegate.getServerAliases(keyType, issuers);
    	logger.info("Called getServerAliases, delegate returned " + 
    				serverAliases.length + " server aliases");
        return serverAliases;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
    	String clientAliases[] = delegate.getClientAliases(keyType, issuers);
    	logger.info("Called getClientAliases, delegate returned " + 
    				clientAliases.length + " client aliases");
        return clientAliases;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
    	PrivateKey privKey = delegate.getPrivateKey(alias);
    	logger.info("Called getPrivateKey with alias " + alias + ", delegated");
        return privKey;
    }
}