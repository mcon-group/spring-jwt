package com.mcg.jwt.api;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import com.mcg.jwt.api.exception.TokenException;
import com.mcg.jwt.api.exception.TokenExpiredException;
import com.mcg.jwt.api.exception.TokenUnreadableException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

public abstract class TokenReader<T> {

	@Autowired
	private PublicKeyProvider publicKeyProvider;
	
	public T readToken(String in) throws TokenException, NoSuchAlgorithmException {
		if(in == null || in.trim().length()==0) return null;
		try {
			return unmap(Jwts.parser().setSigningKeyResolver(new Resolver()).parseClaimsJws(in).getBody()); 
		} catch (ExpiredJwtException e1) {
			throw new TokenExpiredException();
		} catch (Exception e) {
			throw new TokenUnreadableException();
		} 
	}

	public abstract T unmap(Map<String,Object> claim);

	public PublicKeyProvider getPublicKeyProvider() {
		return publicKeyProvider;
	}

	public void setPublicKeyProvider(PublicKeyProvider privateKeyProvider) {
		this.publicKeyProvider = privateKeyProvider;
	}
	
	
	private class Resolver implements SigningKeyResolver {

		public Key resolveSigningKey(JwsHeader header, Claims claims) {
			try {
				return publicKeyProvider.getKey(Long.parseLong(header.get("serial")+""));
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("could not find key to verify signature!");
			}
		}

		public Key resolveSigningKey(JwsHeader header, String plaintext) {
			try {
				return publicKeyProvider.getKey(Long.parseLong(header.get("serial")+""));
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("could not find key to verify signature!");
			}
		}
		
	}
	
	
	
}
