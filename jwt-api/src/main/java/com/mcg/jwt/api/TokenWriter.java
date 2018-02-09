package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public abstract class TokenWriter<T> {
	
	@Autowired
	private PrivateKeyProvider privateKeyProvider;
	
	public String createToken(T in, Date expires) throws NoSuchAlgorithmException {
		long serial = privateKeyProvider.getCurrentSerial();
		PrivateKey key = privateKeyProvider.getPrivateKey(serial);
		JwtBuilder b = Jwts.builder();
		b = b.setHeaderParam("serial", serial+"");
		b = b.setExpiration(expires);
		b = b.addClaims(map(in));
		if(privateKeyProvider.getAlgorithm().equals("RSA")) {
			b = b.signWith(SignatureAlgorithm.RS256, key);
		} else if(privateKeyProvider.getAlgorithm().equals("EC")) {
			b = b.signWith(SignatureAlgorithm.ES256, key);
		} else {
			throw new NoSuchAlgorithmException();
		}
		return b.compact();
		
	}
	
	public abstract Map<String,Object> map(T in);

	public PrivateKeyProvider getPrivateKeyProvider() {
		return privateKeyProvider;
	}

	public void setPrivateKeyProvider(PrivateKeyProvider publicKeyProvider) {
		this.privateKeyProvider = publicKeyProvider;
	}
	
}
