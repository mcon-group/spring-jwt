package com.mcg.jwt;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public interface KeyGenerator {

	public KeyPair generateKeyPair() throws NoSuchAlgorithmException;

}
