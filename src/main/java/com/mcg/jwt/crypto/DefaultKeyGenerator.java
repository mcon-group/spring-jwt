package com.mcg.jwt.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.mcg.jwt.KeyGenerator;

@Service
public class DefaultKeyGenerator implements KeyGenerator {

	@Value("${jwt.algo:'EC'}")
	private String algorithm = "EC";
	
	@Value("${jwt.ec.curve:'secp384r1'}")
	private String ecCurve = "secp384r1";
	
	public DefaultKeyGenerator() {
	}

	public DefaultKeyGenerator(String algorithm) {
		this.algorithm = algorithm;
	}
	
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		if(algorithm.equals("RSA")) return generateRsaKeyPair();
		if(algorithm.equals("EC")) return generateEcKeyPair();
		throw new NoSuchAlgorithmException();
	}
	
	public KeyPair generateRsaKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(4096,new SecureRandom());
			return kpg.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e); 
		}
	}
	
	public KeyPair generateEcKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		    kpg.initialize(new ECGenParameterSpec(ecCurve),new SecureRandom());
			return kpg.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e); 
		}
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}
	
}
