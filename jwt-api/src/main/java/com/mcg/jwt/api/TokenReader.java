package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.mcg.jwt.api.exception.TokenException;
import com.mcg.jwt.api.exception.TokenExpiredException;
import com.mcg.jwt.api.exception.TokenUnreadableException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

public abstract class TokenReader<T> {

	private static Log log = LogFactory.getLog(TokenReader.class);
	
	@Autowired
	private PublicKeyProvider publicKeyProvider;
	
	public T readToken(String in) throws TokenException, NoSuchAlgorithmException {
		
		if(in == null || in.trim().length()==0) return null;
		
		log.info("public key provider: "+publicKeyProvider.getClass());

		List<PublicKey> pks = getPublicKeyProvider().getKeys();
		for(PublicKey key : pks) {
			log.debug("reading token: "+(pks.indexOf(key))+" / "+pks.size()+" --- "+key.getAlgorithm()+":"+Base64.getEncoder().encodeToString(key.getEncoded()));
			try {
				return unmap(Jwts.parser().setSigningKey(key).parseClaimsJws(in).getBody()); 
			} catch (ExpiredJwtException e1) {
				log.error("token expired: ",e1);
				throw new TokenExpiredException();
			} catch (Exception e2) {
				log.error("token unreadable: ",e2);
			}
		}
		throw new TokenUnreadableException();
	}

	public abstract T unmap(Map<String,Object> claim);

	public PublicKeyProvider getPublicKeyProvider() {
		return publicKeyProvider;
	}

	public void setPublicKeyProvider(PublicKeyProvider privateKeyProvider) {
		this.publicKeyProvider = privateKeyProvider;
	}
	
	
	
	
}
