package com.mcg.jwt;

import java.security.NoSuchAlgorithmException;

import com.mcg.jwt.entities.EncodedPublicKey;

public interface PublicKeyProvider {

	public EncodedPublicKey getPublicKey(long serial) throws NoSuchAlgorithmException;
	
}
