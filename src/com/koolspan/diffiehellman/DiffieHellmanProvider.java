package com.koolspan.diffiehellman;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import android.util.Log;

public class DiffieHellmanProvider {

	private static final BigInteger mP = new BigInteger("158307202229964085518858779003997049237119346816903004777436920523291138469150877443837037411651490011598020631222588358396346433201300189447999207523542179801363373129990182509585388401396150523497008965493023897655686302183689991561848134415584447552527802812795301023029017207019452919813369082132035367139"); //values[0]);
	private static final BigInteger mG = new BigInteger("33100965357485770643567417838047372905693785253889912209261141573484749445021715267723668398202194418713540696773055110903650311100720806320153481159237514300132389263707487062274801920875102648549459674392036956557994021534413819190727471057291161815282940089579819952765839658567864398072173640514447334689"); //values[1]);
	private static final String 	LOG_TAG = "DiffieHellmanProvider";
	private PrivateKey 				mPrivateKey;
	private PublicKey 				mPublicKey;
	private static Random 			mRandomNum = new Random();
	

	public DiffieHellmanProvider()  {
		super();
			
		// Retrieve the prime, base, and private value for generating the key pair.
		// If the values are encoded as in
		// Generating a Parameter Set for the Diffie-Hellman Key Agreement Algorithm,
		// the following code will extract the values.
		
		//
		// The private number should be random.
		//
		int l = randInt(1, Integer.MAX_VALUE);
		Log.d(LOG_TAG, " value are p = " + mP + " g = " + mG + " l = " + l);
		
		//
		// Now generate the keys.
		//
		try {
			generateKeys(mP, mG, l);
		} catch (Exception e) {
			Log.d(LOG_TAG, "Exception has been thrown " + e);
			e.printStackTrace();
		}
	}

	public byte[] getRawPublicKey() {
		return mPublicKey.getEncoded();
	}
	
	public static int randInt(int min, int max) {
	   // nextInt is normally exclusive of the top value,
	    // so add 1 to make it inclusive
	    int randomNum = mRandomNum .nextInt((max - min) + 1) + min;
	    return randomNum;
	}
	
	private void generateKeys(BigInteger p, BigInteger g, int l)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		 //
		 // Use the values to generate a key pair
		 //
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
		 DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
		 keyGen.initialize(dhSpec);
		 KeyPair keypair = keyGen.generateKeyPair();
		 
		 Log.d(LOG_TAG, " generated a keypair");
		 mPrivateKey = keypair.getPrivate();
		 mPublicKey = keypair.getPublic();
	}
	
	
	public SecretKey generateSharedSecret(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		Log.d(LOG_TAG, " generateSharedSecret with public key =  " + publicKeyBytes);
		
		//
		// Make a real key out of it.
		//
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFact = KeyFactory.getInstance("DH");
		PublicKey publicKey = keyFact.generatePublic(x509KeySpec);
		
		//
		// Prepare to generate the secret key with the private key and public key of the other party
		//
		KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		keyAgreement.init(mPrivateKey); 													// Add this users private key.
		keyAgreement.doPhase(publicKey, /* last phase of the agreement */true);			// Add the known public key.
		
		//
		// Specify the type of key to generate;
		// see Listing All Available Symmetric Key Generators
		String algorithm = "DES";
		SecretKey secretKey = keyAgreement.generateSecret(algorithm);
		
		return secretKey;
	}
}
