package com.mcg.jwt;

import java.security.NoSuchAlgorithmException;

import com.mcg.jwt.entities.EncodedPrivateKey;

public interface PrivateKeyProvider {

	public EncodedPrivateKey getPrivateKey() throws NoSuchAlgorithmException;

}
