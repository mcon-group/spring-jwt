package com.mcg.jwt;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import com.mcg.jwt.entities.EncodedPrivateKey;
import com.mcg.jwt.exception.config.JwtConfig;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;

public abstract class TokenWriter<T> {
	
	@Autowired
	private JwtConfig config;
	
	@Autowired
	private PrivateKeyProvider privateKeyProvider;
	
	public String createToken(T in, Date expires) throws NoSuchAlgorithmException {
		EncodedPrivateKey epk = privateKeyProvider.getPrivateKey();
		JwtBuilder b = Jwts.builder();
		b = b.setHeaderParam("serial", epk.getSerial()+"");
		b = b.setExpiration(expires);
		b = b.addClaims(map(in));
		if(config.isGzip()) {
			b = b.compressWith(new GzipCompressionCodec());
		}
		if(epk.getAlgorithm().equals("RSA")) {
			b = b.signWith(SignatureAlgorithm.RS256, epk.getPrivateKey());
		} else if(epk.getAlgorithm().equals("EC")) {
			b = b.signWith(SignatureAlgorithm.ES256, epk.getPrivateKey());
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
