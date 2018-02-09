package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

public interface PrivateKeyProvider {

	public PrivateKey getPrivateKey(long serial) throws NoSuchAlgorithmException;
	
	public long getCurrentSerial();
	
	public String getAlgorithm();

}
