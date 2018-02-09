package com.mcg.jwt.api.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

import com.mcg.jwt.api.PrivateKeyProvider;
import com.mcg.jwt.api.PublicKeyProvider;

public class DefaultKeyProvider implements PrivateKeyProvider, PublicKeyProvider {

	private DefaultKeyGenerator kg = new DefaultKeyGenerator();
	private KeyPair kp;
	private String algorithm;
	
	private void getKeyPair() throws NoSuchAlgorithmException {
		if(kp==null) {
			kg.setAlgorithm(algorithm);
			try {
				kp = kg.generateKeyPair();
			} catch (NoSuchAlgorithmException e) {
				throw new NoSuchAlgorithmException();
			}
		}
	}
	
	public List<PublicKey> getKeys() throws NoSuchAlgorithmException {
		getKeyPair();
		return Collections.singletonList(kp.getPublic());
	}

	public PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
		getKeyPair();
		return kp.getPrivate();
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}
	
	

}
