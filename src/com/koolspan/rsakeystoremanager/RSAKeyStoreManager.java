package com.koolspan.rsakeystoremanager;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;

import android.security.KeyPairGeneratorSpec;
import android.util.Log;
import android.view.View;

import com.koolspan.certificatehelper.CertificateHelper;

/**
 * Class to store and manage RSA keys in the AndroidKeyStore.
 */
public class RSAKeyStoreManager {

	//
	// The name of the management certificate saved in the keystore.
	//
	public static final String MANAGEMENT_CERTIFICATES_ALIAS = "ManagementCert";

	//
	// Tag for the log.
	//
	private static final String TAG = "RSAKeyStoreManager";
	
	//
	// Keystore (AndroidKeystoreProvider).
	//
	private KeyStore mKeyStore;

	/**
	 * Using the Android Key store to create/delete and store RSA keys.
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public RSAKeyStoreManager() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		super();
		mKeyStore = KeyStore.getInstance("AndroidKeyStore");
		mKeyStore.load(null);
	}

	/**
	 * Create an store an RSA key. Stored in Android's Keystore database.
	 * 
	 * @param view Associated view to get context.
	 * @param alias Name of the key.
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 */

	public KeyPair createNewCertificate(View view, String alias)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, KeyStoreException {
		KeyPair keyPair = null;

		if (!mKeyStore.containsAlias(alias)) {
			Calendar start = Calendar.getInstance();
			Calendar end = Calendar.getInstance();
			end.add(Calendar.YEAR, 1);

			KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(
					view.getContext())
					.setAlias(alias)
					.setSubject( new X500Principal("CN=Sample Name, O=Android Authority"))
					.setSerialNumber(BigInteger.ONE)
					.setStartDate(start.getTime()).setEndDate(end.getTime())
					.build();
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
					"AndroidKeyStore");
			generator.initialize(spec);

			keyPair = generator.generateKeyPair();
		}

		return keyPair;
	}

	/**
	 * Delete an existing key.
	 * 
	 * @param view Associated view to get context.
	 * @param alias Name of the key.
	 * @throws KeyStoreException
	 */
	public void deleteCertificate(String alias) throws KeyStoreException {
		mKeyStore.deleteEntry(alias);
	}

	/**
	 * Get a private key from Android's keystore area.
	 * 
	 * @param alias the name of the key.
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 */
	public PrivateKeyEntry getPrivateKeyEntry(String alias)
			throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException {
		return (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, null);
	}

	/**
	 * Get a public key from Android's keystore area.
	 * 
	 * @param alias the name of the key.
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 */
	public PublicKey getPublicKeyEntry(String alias)
			throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException {
		Certificate cert = mKeyStore.getCertificate(alias);
		final PublicKey publicKey = cert.getPublicKey();
		return publicKey;
	}

	/**
	 * Get a key pair from the alias.
	 * 
	 * @param alias Name of the key pair.
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 */
	public KeyPair getKeyPairEntry(String alias)
			throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException {
		Certificate cert = mKeyStore.getCertificate(alias);
		final Key key = ((PrivateKey) getPrivateKeyEntry(alias).getPrivateKey());
		final PublicKey publicKey = cert.getPublicKey();
		return new KeyPair(publicKey, (PrivateKey) key);
	}

	/**
	 * Return the certificate associated with the keys alias.
	 * 
	 * @param alias String of a cert in keystore.
	 * @return
	 * @throws KeyStoreException
	 */
	public Certificate getCertificate(String alias) throws KeyStoreException {
		return mKeyStore.getCertificate(alias);
	}

	/**
	 * Get a list of all the key names/aliases.
	 * 
	 * @return list of all keys.
	 * @throws KeyStoreException
	 */
	public Enumeration<String> aliases() throws KeyStoreException {
		return mKeyStore.aliases();
	}

	/**
	 * This method will sign message with RSA 2048 key
	 * 
	 * @return byte[]
	 */
	public byte[] sign(String message, String keyAlias) throws Exception {
		KeyPair keyPair = getKeyPairEntry(keyAlias);
		PrivateKey priv = keyPair.getPrivate();
		PublicKey pub = keyPair.getPublic();

		Log.d(TAG, "RSAPub key Mod for Sign/Verify  : " + CertificateHelper.toHex(((RSAPublicKey) pub).getModulus().toByteArray()));
		Log.d(TAG, "RSAPub key Exp for Sign/Verify  : " + CertificateHelper.toHex(((RSAPublicKey) pub).getPublicExponent().toByteArray()));

		// sign
		Signature dsa = Signature.getInstance("SHA256withRSA");
		dsa.initSign(priv);

		dsa.update(message.getBytes());
		byte[] realSig = dsa.sign();
		Log.d(TAG, "RSA Sign-Data   : " + CertificateHelper.toHex(realSig));
		return realSig;
	}

	/**
	 * This method verify signature with RSA public key
	 * 
	 * @param message The plain message
	 * @param rsaMOD RSA Public key Modulus in string
	 * @param rsaEXP RSA Public key Exponent in string
	 * @param rsaSignData Signature which will be verified
	 * @return true if verifications success, false otherwise
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */

	public boolean verifySignedText(byte[] data, byte[] signatureBytes,
			String keyNameAlias) throws KeyStoreException,
			NoSuchAlgorithmException, Exception {
		//
		// Get the public key.
		//
		Certificate cert = mKeyStore.getCertificate(keyNameAlias);
		PublicKey publicKey = cert.getPublicKey();

		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(data);

		return signature.verify(signatureBytes);
	}

	/**
	 * Read in a PEM certificate from a string.
	 * @param pemString
	 * @return
	 */
/*	public X509Certificate readInPem(String pemString) {
		try {
			PemReader reader = new PemReader(new StringReader(pemString));
			PemObject pemObject = reader.readPemObject();
			reader.close();

			ByteArrayInputStream bIn = new ByteArrayInputStream(
					pemObject.getContent());
			CertificateFactory certFact = CertificateFactory
					.getInstance("X.509");
			return (X509Certificate) certFact.generateCertificate(bIn);
		} catch (Exception e) {
			Log.d("RSAKeyStoreManager", "problem parsing cert: " + e.toString());
		}

		return null;
	}
	*/

	/**
	 * Read in a PEM string and store it in keystore as a management key.
	 * 
	 * @param pemString
	 */
	public void importManagementPemToKeystore(String pemString) {
		try {
			PemReader reader = new PemReader(new StringReader(pemString));
			PemObject pemObject = reader.readPemObject();
			reader.close();

			ByteArrayInputStream bIn = new ByteArrayInputStream(
					pemObject.getContent());
			CertificateFactory certFact = CertificateFactory
					.getInstance("X.509");
			X509Certificate cert = (X509Certificate) certFact
					.generateCertificate(bIn);

			mKeyStore.setCertificateEntry(MANAGEMENT_CERTIFICATES_ALIAS, cert);
		} catch (Exception e) {
			Log.d("RSAKeyStoreManager", "problem parsing cert: " + e.toString());
		}
	}

	/**
	 * Get all the peer to peer certificates.
	 * 
	 * @return List<Certificate>
	 */
	public List<Certificate> getAllPeerToPeerCertificates() {
		List<Certificate> listOfCerts = new LinkedList<Certificate>();

		try {
			Enumeration<String> aliases = mKeyStore.aliases();
			while (aliases.hasMoreElements()) {
				String nextElement = aliases.nextElement();
				if (!nextElement.equalsIgnoreCase(MANAGEMENT_CERTIFICATES_ALIAS)) {
					listOfCerts.add(getCertificate(nextElement));
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		return listOfCerts;
	}

	/**
	 * Delete all the certificates in the keystore.
	 * 
	 * @throws KeyStoreException
	 */
	public void clearCertificates() throws KeyStoreException {
		Enumeration<String> aliases = mKeyStore.aliases();
		while (aliases.hasMoreElements()) {
			String nextElement = aliases.nextElement();
			mKeyStore.deleteEntry(nextElement);
		}
	}
	
	/**
	 * Get only the management certificate. 
	 * @return Certificate.
	 * @throws KeyStoreException
	 */
	public Certificate getManagementCertificate() throws KeyStoreException {
		return getCertificate(MANAGEMENT_CERTIFICATES_ALIAS);
	}

}
