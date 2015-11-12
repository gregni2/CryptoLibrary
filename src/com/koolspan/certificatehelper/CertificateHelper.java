package com.koolspan.certificatehelper;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v1CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

public class CertificateHelper {
	
	/**
	 * Given a keypair. Create a self signed certificate. 
	 * 
	 * @param keyPair
	 * @return
	 * @throws OperatorCreationException
	 */
    public static X509CertificateHolder getSelfSignedCertificate(KeyPair keyPair) throws OperatorCreationException {
        //
        // Make a content signer. Using the private key.
        //
    	JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        PrivateKey aKeyPrivate = keyPair.getPrivate();
        ContentSigner contentSigner = csBuilder.build(aKeyPrivate);

        //
        // Setup the dates and the name.
        //
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);
        X500Principal x500Principal = new X500Principal("CN=Test");

        //
        // Create a self signed certificate.
        //
        X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(x500Principal, BigInteger.ONE, startDate, endDate, x500Principal, keyPair.getPublic());
        X509CertificateHolder cert = v1CertGen.build(contentSigner);

        return cert;
    }
    
    /**
     * Write the certificate information to standard out.
     * @param cert
     */
    
    public static void writeoutCertificate(X509CertificateHolder cert) {
        System.out.println("=====================");
        System.out.println("CERTIFICATE TO_STRING");

        System.out.println();
        System.out.println(cert);
        System.out.println();

        System.out.println("=====================");
        System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");

        System.out.println();
        PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
        try {
            pemWriter.writeObject(cert);
            pemWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println();
    }
    
    /**
     * Dump a byte array to a string.
     * @param byteArray
     * @return
     */
    public static String toHex(byte[] byteArray) {
		   StringBuilder sb = new StringBuilder(byteArray.length * 2);
		   for(byte b: byteArray)
		      sb.append(String.format("%02x", b & 0xff));
		   return sb.toString();
    }

    /**
     * Create a CSR using the keypair passed in. 
     * @param pair KeyPair
     * @return
     * @throws OperatorCreationException
     */
    public static PKCS10CertificationRequest createCSR(KeyPair pair) throws OperatorCreationException {    	
    	X500Principal x500Principal = new X500Principal("CN=Requested Test Certificate");
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(x500Principal, pair.getPublic());

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(pair.getPrivate());

        return p10Builder.build(signer);
    }
    
    /**
     * Write out a certificate to PEM format string.
     * @param certificate X509Certificate.
     * @return string of PEM format.
     */
    public static String convertToPEMFormat(final X509Certificate certificate){
    	  try {
    	    StringWriter stringWriter=new StringWriter();
    	    PemWriter pemWriter = new PemWriter(stringWriter);
    	    pemWriter.writeObject(new PemObject(certificate.getType(),certificate.getEncoded()));
    	    pemWriter.flush();
    	    return stringWriter.toString();
    	  }
    	 catch (  IOException e) {
    	    throw new RuntimeException("Cannot format certificate to PEM format",e);
    	  }
    	catch (  CertificateEncodingException e) {
    	    throw new RuntimeException("Cannot format certificate to PEM format",e);
    	}
    }
    
}
