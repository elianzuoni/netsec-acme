package elianzuoni.netsec.acme.csr;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;


public class Csr {
	
	private static Logger logger = Logger.getLogger("elianzuoni.netsec.acme.csr.Csr");
	
	public static String generateCsr(KeyPair keypair, Collection<String> domains) throws Exception {
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
	            new X500Principal("CN=MyAcme"), keypair.getPublic());
		
		// Accumulate all the domains in this GeneralName list
		Collection<GeneralName> domainsGeneralNameList = new ArrayList<GeneralName>(domains.size());
		for(String domain : domains) {
			GeneralName domainGeneralName = new GeneralName(GeneralName.dNSName, domain);
			domainsGeneralNameList.add(domainGeneralName);
		}
		// Transform to GeneralNames
		GeneralNames domainsGeneralNames = new GeneralNames(
				domainsGeneralNameList.toArray(new GeneralName[0]));
		// Transform to octet string
		DEROctetString sansOctetString = new DEROctetString(domainsGeneralNames.getEncoded());
		
		/*
		ByteArrayOutputStream domainsBaos = new ByteArrayOutputStream();
		for(String domain : domains) {
			domainsBaos.write(0x82);
			domainsBaos.write((byte)domain.length());
			domainsBaos.write(domain.getBytes());
		}
		byte domainsBytes[] = domainsBaos.toByteArray();
		
		ByteArrayOutputStream sansBaos = new ByteArrayOutputStream();
		sansBaos.write(0x30);
		sansBaos.write((byte)domainsBytes.length);
		sansBaos.write(domainsBytes);
		byte sansBytes[] = sansBaos.toByteArray();
		DEROctetString sansOctetString = new DEROctetString(sansBytes);
		*/
		
		// Build the SAN extension
		ASN1ObjectIdentifier sanOid = new ASN1ObjectIdentifier("2.5.29.17");
		DLSequence sanExtension = new DLSequence(new ASN1Encodable[] {sanOid, sansOctetString});
		
		// Build the extensions sequence, with just the SAN extension
		DLSequence extensions = new DLSequence(sanExtension);

		// Add the extensions to the CSR builder
		ASN1ObjectIdentifier extensionsRequestOid = new ASN1ObjectIdentifier("1.2.840.113549.1.9.14");
		p10Builder.addAttribute(extensionsRequestOid, extensions);
	    
		// Alternative that doesn't work in PEM
		/*
	    List<GeneralName> namesList = new ArrayList<GeneralName>();
	    namesList.add(new GeneralName(GeneralName.dNSName, new DERIA5String("mammeta.soreta.tu")));
	    namesList.add(new GeneralName(GeneralName.dNSName, new DERIA5String("pateto.frateto.tu")));
	    GeneralNames subjectAltNames = new GeneralNames(namesList.toArray(new GeneralName[]{}));
	    ExtensionsGenerator extGen = new ExtensionsGenerator();
	    extGen.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);
	    p10Builder.addAttribute(Extension.subjectAlternativeName, extGen.generate());
	    */
	    
		/*
	    p10Builder.addAttribute(Extension.subjectAlternativeName, new DERIA5String("mammeta.soreta.tu"));
	    p10Builder.addAttribute(Extension.subjectAlternativeName, new DERIA5String("pateto.frateto.tu"));
	    */
	    
	    // Just reference
	    /*
	    ASN1ObjectIdentifier attrType = new ASN1ObjectIdentifier("2.5.29.17");
	    Extensions extensions;
		ASN1ObjectIdentifier extOID = X509Extensions.SubjectAlternativeName;
		ASN1Encodable value = GeneralNames.fromExtensions(extensions, extOID);
		ASN1Encodable attrValue1 = new GeneralName(GeneralName.dNSName, "example.com");
		ASN1Encodable attrValue2 = new GeneralName(GeneralName.dNSName, "soreta.com");
		p10Builder.addAttribute(attrType , attrValue1);
		p10Builder.addAttribute(attrType , attrValue2);
		*/

	    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
	    ContentSigner signer = csBuilder.build(keypair.getPrivate());
	    PKCS10CertificationRequest csr = p10Builder.build(signer);
	    
	    // Log the CSR in PEM format
	    StringWriter csrPemStringWriter = new StringWriter();
	    JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(csrPemStringWriter);
	    jcaPEMWriter.writeObject(csr);
	    jcaPEMWriter.close();
	    logger.info("Generated CSR. PEM version:\n" + csrPemStringWriter.toString());
	    
	    // Return the base64url-encoded DER version of the CSR
	    byte hopefullyDer[] = csr.getEncoded();	// This is indeed DER for PKs and signatures
	    return Base64.getUrlEncoder().withoutPadding().encodeToString(hopefullyDer);
	}
}
