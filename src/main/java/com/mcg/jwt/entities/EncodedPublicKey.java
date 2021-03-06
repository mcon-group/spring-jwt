package com.mcg.jwt.entities;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class EncodedPublicKey {
	
	private long serial;
	
	private String key;

	private String algorithm;
	
	private Date issued;
	private Date notAfter;
	
	
	public long getSerial() {
		return serial;
	}

	
	public void setSerial(long serial) {
		this.serial = serial;
	}

	
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
	public void setPublicKey(PublicKey publicKey) {
		this.algorithm = publicKey.getAlgorithm();
		this.key = Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}
	
	
	@JsonIgnore
	public PublicKey getPublicKey() {
		try {
			X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
			KeyFactory kf = KeyFactory.getInstance(algorithm);		
			return kf.generatePublic(spec); 
		} catch (Exception e) {
			throw new RuntimeException("unreadable public key");
		}
	}

	
	public Date getNotAfter() {
		return notAfter;
	}

	
	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	
	public Date getIssued() {
		return issued;
	}

	
	public void setIssued(Date issued) {
		this.issued = issued;
	}
	
	
}
