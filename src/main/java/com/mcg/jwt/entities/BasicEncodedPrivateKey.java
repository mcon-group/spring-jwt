package com.mcg.jwt.entities;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class BasicEncodedPrivateKey implements EncodedPrivateKey {
	
	private long serial;
	
	private String key;

	private String algorithm;
	
	private Date notAfter;
	
	@Override
	public long getSerial() {
		return serial;
	}

	public void setSerial(long serial) {
		this.serial = serial;
	}

	@Override
	public String getAlgorithm() {
		return algorithm;
	}
	
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}
	
	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}
	
	@JsonIgnore
	public void setPrivateKey(PrivateKey privateKey) {
		this.algorithm = privateKey.getAlgorithm();
		this.key = Base64.getEncoder().encodeToString(privateKey.getEncoded());
	}
	
	@Override
	@JsonIgnore
	public PrivateKey getPrivateKey() {
		try {
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
			KeyFactory kf = KeyFactory.getInstance(algorithm);		
			return kf.generatePrivate(spec); 
		} catch (Exception e) {
			throw new RuntimeException("unreadable public key");
		}
	}

	@Override
	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}
	
	
}
