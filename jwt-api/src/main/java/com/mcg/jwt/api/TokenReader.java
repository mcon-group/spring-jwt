package com.mcg.jwt.api;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import com.mcg.jwt.api.exception.TokenException;
import com.mcg.jwt.api.exception.TokenExpiredException;
import com.mcg.jwt.api.exception.TokenUnreadableException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

@EnableScheduling
public abstract class TokenReader<T> {

	@Autowired
	private PublicKeyProvider publicKeyProvider;
	
	private Resolver resolver = new Resolver();
	
	public String getString(Map<String,Object> claims, String claimName, String def) {
		if(claims.get(claimName)==null) return def;
		return claims.get(claimName).toString();
	}
	
	public boolean getBoolean(Map<String,Object> claims, String claimName, boolean def) {
		if(claims.get(claimName)==null) return def;
		return ((Boolean)claims.get(claimName)).booleanValue();
	}
	
	public T readToken(String in) throws TokenException, NoSuchAlgorithmException {
		if(in == null || in.trim().length()==0) return null;
		try {
			return unmap(Jwts.parser().setSigningKeyResolver(resolver).parseClaimsJws(in).getBody()); 
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
	
	
	@Scheduled(fixedDelay=1000*60*60*24)
	public void flushKeys() {
		resolver.keys.clear();
	}
	
	private class Resolver implements SigningKeyResolver {
		
		private Map<String,Key> keys;

		public Key resolveSigningKey(JwsHeader header, Claims claims) {
			return (resolveSigningKey(header, ""));
		}

		public Key resolveSigningKey(JwsHeader header, String plaintext) {
			try {
				Long s = Long.parseLong(header.get("serial")+"");
				Key k = keys.get(s);
				if(k==null) {
					k = publicKeyProvider.getKey(s);
					keys.put(s.toString(), k);
				}
				return k;
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("could not find key to verify signature!");
			}
		}
		
	}
	
	
	
}
