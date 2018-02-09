package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;

public interface PublicKeyProvider {

	public List<PublicKey> getKeys() throws NoSuchAlgorithmException;
	
	public PublicKey getKey(long serial) throws NoSuchAlgorithmException;
	
}
