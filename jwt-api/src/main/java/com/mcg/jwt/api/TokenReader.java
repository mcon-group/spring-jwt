package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import com.mcg.jwt.api.exception.TokenException;
import com.mcg.jwt.api.exception.TokenExpiredException;
import com.mcg.jwt.api.exception.TokenUnreadableException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

public abstract class TokenReader<T> {

	@Autowired
	private PublicKeyProvider publicKeyProvider;
	
	public T readToken(String in) throws TokenException, NoSuchAlgorithmException {
		for(PublicKey key : getPublicKeyProvider().getKeys()) {
			try {
				return unmap(Jwts.parser().setSigningKey(key).parseClaimsJws(in).getBody()); 
			} catch (ExpiredJwtException e1) {
				throw new TokenExpiredException();
			} catch (Exception e2) {
				throw new TokenUnreadableException();
			}
		}
		return null;
	}

	public abstract T unmap(Map<String,Object> claim);

	public PublicKeyProvider getPublicKeyProvider() {
		return publicKeyProvider;
	}

	public void setPublicKeyProvider(PublicKeyProvider privateKeyProvider) {
		this.publicKeyProvider = privateKeyProvider;
	}
	
	
	
	
}
