package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;

import com.mcg.jwt.api.entities.EncodedPrivateKey;

public interface PrivateKeyProvider {

	public EncodedPrivateKey getPrivateKey() throws NoSuchAlgorithmException;

}
