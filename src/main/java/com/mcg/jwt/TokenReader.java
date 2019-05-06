package com.mcg.jwt;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.mcg.jwt.entities.EncodedPublicKey;
import com.mcg.jwt.exception.TokenException;
import com.mcg.jwt.exception.TokenExpiredException;
import com.mcg.jwt.exception.TokenUnreadableException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

@EnableScheduling
public abstract class TokenReader<T> {

	private static Log log = LogFactory.getLog(TokenReader.class);
	
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
			log.debug("reading token: "+in);

			log.debug("creating parser with public key provider: "+publicKeyProvider.getClass());
			JwtParser p = Jwts.parser();
			p = p.setSigningKeyResolver(resolver);
			
			log.debug("parsing body ... ");
			Map<String,Object> m = Jwts.parser().setSigningKeyResolver(resolver).parseClaimsJws(in).getBody();
			log.debug("mapping body ... ");

			T t = unmap(m);
			if(log.isDebugEnabled()) {
				try {
					String s = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(t);
					log.debug("mapped object: "+s);
				} catch (Exception e) {
					log.error("unable to map object: ",e);
					throw new TokenUnreadableException();
				}
			}
			return t;
		} catch (ExpiredJwtException e1) {
			log.error("JWT expired ("+e1.getMessage()+")",e1);
			throw new TokenExpiredException();
		} catch (Exception e2) {
			log.error("JWT invalid: ("+e2.getClass().getSimpleName()+":"+e2.getMessage()+")",e2);
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
		
		private Map<Long,Key> keys = new HashMap<Long, Key>();

		public Key resolveSigningKey(@SuppressWarnings("rawtypes") JwsHeader header, Claims claims) {
			return (resolveSigningKey(header, ""));
		}

		public Key resolveSigningKey(@SuppressWarnings("rawtypes") JwsHeader header, String plaintext) {
			try {
				log.debug("resolving signing key: "+header.get("serial"));
				if(header.get("serial")==null) return null;
				Long s = Long.parseLong(header.get("serial")+"");
				Key k = keys.get(s);
				if(k==null) {
					log.debug("resolving signing key: "+header.get("serial")+" NOT found in cache!");
					EncodedPublicKey epubKey = publicKeyProvider.getPublicKey(s);
					if(epubKey == null) {
						throw new RuntimeException("could not find key for serial: "+s);
					} else if (epubKey.getNotAfter()==null) {
						//no
					} else if (epubKey.getNotAfter().before(new Date())) {
						throw new RuntimeException("key found for serial: "+s+" is no longer valid (expired: "+epubKey.getNotAfter()+")");
					}
					k = epubKey.getPublicKey();
					keys.put(s, k);
				} else {
					log.debug("resolving signing key: "+header.get("serial")+" found in cache!");
				}
				if(k==null) {
					throw new Exception("error resolving signing key");
				}
				return k;
			} catch (Exception e) {
				log.warn("error resolving signing key",e);
				throw new RuntimeException("could not find key to verify signature!");
			}
		}
		
	}
	
	
	
}
