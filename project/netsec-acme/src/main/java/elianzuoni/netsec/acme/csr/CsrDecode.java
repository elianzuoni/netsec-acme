package elianzuoni.netsec.acme.csr;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CsrDecode {
	private final X500Name x500Name;
	private PKCS10CertificationRequest pkcs10;

	public CsrDecode(Reader pemReader ) throws IOException {
		final PEMParser pemParser = new PEMParser(pemReader);
		pkcs10 = ((PKCS10CertificationRequest) pemParser.readObject());
		x500Name = pkcs10.getSubject();
	}

	public String get(final CSRObjectEnum field) {
		RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(field.code));
		String retVal = null;
		for (RDN item : rdnArray) {
			retVal = item.getFirst().getValue().toString();
		}
		return retVal;
	}

	PKCS10CertificationRequest getPkcs10() {
		return pkcs10;
	}

	public enum CSRObjectEnum {
		COUNTRY("2.5.4.6"), STATE("2.5.4.8"), LOCALE("2.5.4.7"), ORGANIZATION("2.5.4.10"),
		ORGANIZATION_UNIT("2.5.4.11"), COMMON_NAME("2.5.4.3"),XT("1.2.840.113549.1.9.14"),SAN("2.5.29.17")
		;

		private final String code;

		CSRObjectEnum(final String sCode) {
			code = sCode;
		}
	}

	public static void main(String[] args) throws IOException {
		
		InputStreamReader r = new InputStreamReader(new FileInputStream("./csr.pem"));
		CsrDecode csr = new CsrDecode(r);
		for (final CSRObjectEnum field : CSRObjectEnum.values()){
	        System.out.println(field.name() + ": " + csr.get(field));
	    }
		PKCS10CertificationRequest pkcs102 = csr.getPkcs10();
		Attribute[] attributes = pkcs102.getAttributes();
		for (int i = 0; i < attributes.length; i++) {
			Attribute a = attributes[i];
			System.out.println(a.getAttrType() + " -> "  + a.toString());
			ASN1Set values = a.getAttrValues();
			for(ASN1Encodable value : values) {
				System.out.println("\t" + value.getClass() + ": " + value.toASN1Primitive());
				DLSequence outerSeq = (DLSequence)value;
				for(ASN1Encodable outerSeqElem : outerSeq) {
					System.out.println("\t\t" + outerSeqElem.getClass() + ": " + outerSeqElem.toASN1Primitive());
					DLSequence innerSeq = (DLSequence)outerSeqElem;
					for(ASN1Encodable innerSeqElem : innerSeq) {
						System.out.println("\t\t\t" + innerSeqElem.getClass() + ": " + innerSeqElem.toASN1Primitive());
					}
				}
			}
		}

	}
}
