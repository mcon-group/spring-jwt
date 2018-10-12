package com.mcg.jwt;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.mcg.jwt.entities.EncodedPublicKey;
import com.mcg.jwt.exception.TokenException;
import com.mcg.jwt.exception.TokenExpiredException;
import com.mcg.jwt.exception.TokenUnreadableException;
import com.mcg.jwt.exception.config.JwtConfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;

@EnableScheduling
public abstract class TokenReader<T> {

	private static Log log = LogFactory.getLog(TokenReader.class);
	
	@Autowired
	private JwtConfig config;
	
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
			JwtParser p = Jwts.parser();
			p = p.setSigningKeyResolver(resolver);
			
			Map<String,Object> m = Jwts.parser().setSigningKeyResolver(resolver).parseClaimsJws(in).getBody();
			log.debug("mapping ... ");
			T t = unmap(m);
			if(log.isDebugEnabled()) {
				try {
					String s = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(t);
					log.debug("mapped object: "+s);
				} catch (Exception e) {
				}
			}
			return t;
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
		
		private Map<String,Key> keys = new HashMap<String, Key>();

		public Key resolveSigningKey(JwsHeader header, Claims claims) {
			return (resolveSigningKey(header, ""));
		}

		public Key resolveSigningKey(JwsHeader header, String plaintext) {
			try {
				log.debug("resolving signing key: "+header.get("serial"));
				Long s = Long.parseLong(header.get("serial")+"");
				if(s == null) return null;
				Key k = keys.get(s);
				if(k==null) {
					EncodedPublicKey epubKey = publicKeyProvider.getPublicKey(s);
					if(epubKey == null) return null; 
					k = epubKey.getPublicKey();
					keys.put(s.toString(), k);
				} else {
					log.warn("resolving signing key: "+header.get("serial")+" not found!");
				}
				return k;
			} catch (Exception e) {
				log.warn("error resolving signing key",e);
				throw new RuntimeException("could not find key to verify signature!");
			}
		}
		
	}
	
	
	
}
