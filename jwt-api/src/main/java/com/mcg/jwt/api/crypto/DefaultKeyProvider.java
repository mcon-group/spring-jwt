package com.mcg.jwt.api.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.mcg.jwt.api.PrivateKeyProvider;
import com.mcg.jwt.api.PublicKeyProvider;

public class DefaultKeyProvider implements PrivateKeyProvider, PublicKeyProvider {

	private DefaultKeyGenerator kg = new DefaultKeyGenerator();
	private Map<Long,KeyPair> keyPairs = new HashMap<Long, KeyPair>();
	private long currentSerial = 0; 
	private String algorithm;
	
	public void createKeyPair(long serial) throws NoSuchAlgorithmException {
		if(serial < currentSerial) {
			throw new RuntimeException("serials should not go down");
		}
		kg.setAlgorithm(algorithm);
		try {
			KeyPair kp = kg.generateKeyPair();
			keyPairs.put(serial, kp);
			this.currentSerial = serial;
		} catch (NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException();
		}
	}
	
	
	private KeyPair getKeyPair(long serial) throws NoSuchAlgorithmException {
		return keyPairs.get(serial);
	}
	
	public List<PublicKey> getKeys() throws NoSuchAlgorithmException {
		List<PublicKey> out = new ArrayList<PublicKey>();
		for(KeyPair kp : keyPairs.values()) {
			out.add(kp.getPublic());
		}
		return out;
	}

	public PrivateKey getPrivateKey(long serial) throws NoSuchAlgorithmException {
		return getKeyPair(serial).getPrivate();
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public PublicKey getKey(long serial) throws NoSuchAlgorithmException {
		return getKeyPair(serial).getPublic();
	}

	public long getCurrentSerial() {
		return currentSerial;
	}
	
	

}
