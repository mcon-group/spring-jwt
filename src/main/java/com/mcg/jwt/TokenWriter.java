package com.mcg.jwt;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import com.mcg.jwt.entities.EncodedPrivateKey;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public abstract class TokenWriter<T> {
	
	@Autowired
	private PrivateKeyProvider privateKeyProvider;
	
	public String createToken(T in, Date expires) throws NoSuchAlgorithmException {
		EncodedPrivateKey epk = privateKeyProvider.getPrivateKey();
		JwtBuilder b = Jwts.builder();
		b = b.setHeaderParam("serial", epk.getSerial()+"");
		b = b.setExpiration(expires);
		b = b.addClaims(map(in));
		if(epk.getAlgorithm().equals("RSA")) {
			b = b.signWith(epk.getPrivateKey(),SignatureAlgorithm.RS256);
		} else if(epk.getAlgorithm().equals("EC")) {
			ECPrivateKey ecpk = (ECPrivateKey) epk.getPrivateKey();
			int bl = ecpk.getParams().getOrder().bitLength();
			if(bl==384) {
				b = b.signWith(epk.getPrivateKey(),SignatureAlgorithm.ES384);
			} else if (bl==256) {
				b = b.signWith(epk.getPrivateKey(),SignatureAlgorithm.ES256);
			} else if (bl==512) {
				b = b.signWith(epk.getPrivateKey(),SignatureAlgorithm.ES512);
			}
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
