package com.mcg.jwt.api;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public interface KeyGenerator {

	public KeyPair generateKeyPair() throws NoSuchAlgorithmException;

}
