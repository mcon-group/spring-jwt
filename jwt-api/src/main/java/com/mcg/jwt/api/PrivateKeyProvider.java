package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

public interface PrivateKeyProvider {

	public PrivateKey getPrivateKey() throws NoSuchAlgorithmException;
	
	public String getAlgorhithm();

}
