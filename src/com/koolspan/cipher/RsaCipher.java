package com.koolspan.cipher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

import android.util.Base64;

import com.koolspan.rsakeystoremanager.RSAKeyStoreManager;

public class RsaCipher {

	private RSAKeyStoreManager mKeyStoreManager;

	/**
	 * Use the keystore passed in to do RSA encryption.
	 * @param keyStoreManager
	 */
	public RsaCipher(RSAKeyStoreManager keyStoreManager) {
		mKeyStoreManager = keyStoreManager;
	}

	/**
	 * Encrypt a sting given a particular alias/key pair name.
	 * @param alias String to the key.
	 * @param textToEncrypt String to encrypt.
	 * @return Encrypted String.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws IOException
	 */
	public String encryptString(String alias, String textToEncrypt) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IOException {
		
		//
		// Get the public and private key.
		//
        RSAPublicKey publicKey = (RSAPublicKey) mKeyStoreManager.getPublicKeyEntry(alias);

        //
        // Create a RSA Cipher.
        //
        Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
        inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //
        // Encypt the text.
        //
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inCipher);
        cipherOutputStream.write(textToEncrypt.getBytes("UTF-8"));
        cipherOutputStream.close();

        byte [] vals = outputStream.toByteArray();
        
        return Base64.encodeToString(vals, Base64.DEFAULT);
	}

	/**
	 * Decrypt a sting given a particular alias/key pair name. 
	 * @param alias String to the key.
	 * @param cipherText encrypted string.
	 * @return Decrypted String.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public String decryptString(String alias, String cipherText) throws 	NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
																			InvalidKeyException, UnrecoverableEntryException, KeyStoreException, IOException {
		//
		// Get the private key.
		//
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)mKeyStoreManager.getPrivateKeyEntry(alias);
		RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
		Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
		output.init(Cipher.DECRYPT_MODE, privateKey);

		//
		// Create a cipher to decrypt the string.
		//
		CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output);
		ArrayList<Byte> values = new ArrayList<Byte>();
		int nextByte;
		while ((nextByte = cipherInputStream.read()) != -1) {
			values.add((byte)nextByte);
		}
		cipherInputStream.close();

		byte[] bytes = new byte[values.size()];
		for(int i = 0; i < bytes.length; i++) {
			bytes[i] = values.get(i).byteValue();
		}
		
		String finalText = new String(bytes, 0, bytes.length, "UTF-8");
		return finalText;
	}
}
