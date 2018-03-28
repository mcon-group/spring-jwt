package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import com.mcg.jwt.api.entities.EncodedPublicKey;

public interface PublicKeyProvider {

	public EncodedPublicKey getPublicKey(long serial) throws NoSuchAlgorithmException;
	
}
