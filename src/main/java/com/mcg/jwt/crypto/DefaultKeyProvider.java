package com.mcg.jwt.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import com.mcg.jwt.PrivateKeyProvider;
import com.mcg.jwt.PublicKeyProvider;
import com.mcg.jwt.entities.BasicEncodedPrivateKey;
import com.mcg.jwt.entities.BasicEncodedPublicKey;
import com.mcg.jwt.entities.EncodedPrivateKey;
import com.mcg.jwt.entities.EncodedPublicKey;

public class DefaultKeyProvider implements PrivateKeyProvider, PublicKeyProvider {

	private DefaultKeyGenerator kg = new DefaultKeyGenerator();
	private Map<Long,BasicEncodedPublicKey> publicKeys = new HashMap<>();
	private EncodedPrivateKey encodedPrivateKey;
	private String algorithm;
	
	public void generateKeyPair() throws NoSuchAlgorithmException {
		kg.setAlgorithm(getAlgorithm());
		try {
			KeyPair kp = kg.generateKeyPair();
			
			
			long serial = System.currentTimeMillis();
			
			BasicEncodedPrivateKey eprivk = new BasicEncodedPrivateKey();
			eprivk.setAlgorithm(getAlgorithm());
			eprivk.setSerial(serial);
			eprivk.setPrivateKey(kp.getPrivate());
			
			BasicEncodedPublicKey epubk = new BasicEncodedPublicKey();
			epubk.setAlgorithm(getAlgorithm());
			epubk.setSerial(serial);
			epubk.setPublicKey(kp.getPublic());
			
			publicKeys.put(serial, epubk);
			this.encodedPrivateKey = eprivk;

		} catch (NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException();
		}
	}

	@Override
	public EncodedPublicKey getPublicKey(long serial) throws NoSuchAlgorithmException {
		return publicKeys.get(serial);
	}

	@Override
	public EncodedPrivateKey getPrivateKey() throws NoSuchAlgorithmException {
		return encodedPrivateKey;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}
	
	

}
