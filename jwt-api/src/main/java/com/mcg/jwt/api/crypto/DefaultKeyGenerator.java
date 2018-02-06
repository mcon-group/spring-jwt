package com.mcg.jwt.api.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.mcg.jwt.api.KeyGenerator;

@Service
public class DefaultKeyGenerator implements KeyGenerator {

	@Value("${jwt.algo:'RSA'}")
	private String algorhithm = "RSA";
	
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		if(algorhithm.equals("RSA")) return generateRsaKeyPair();
		if(algorhithm.equals("EC")) return generateEcKeyPair();
		throw new NoSuchAlgorithmException();
	}
	
	public KeyPair generateRsaKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(4096);
			return kpg.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e); 
		}
	}
	
	public KeyPair generateEcKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		    kpg.initialize(new ECGenParameterSpec("secp192k1"));
			return kpg.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e); 
		}
	}

	public String getAlgorhithm() {
		return algorhithm;
	}

	public void setAlgorhithm(String algorhithm) {
		this.algorhithm = algorhithm;
	}
	
}
