package com.mcg.jwt.api.token;

import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;

import org.springframework.beans.factory.annotation.Autowired;

import com.mcg.jwt.PrivateKeyProvider;
import com.mcg.jwt.crypto.DefaultKeyProvider;
import com.mcg.jwt.entities.EncodedPrivateKey;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.EncodingException;

public class ShortToken {
	
	
	private static DefaultKeyProvider kp = new DefaultKeyProvider();

	private static void testShortToken() throws NoSuchAlgorithmException {
		kp.setAlgorithm("EC");
		kp.generateKeyPair();
		EncodedPrivateKey epk = kp.getPrivateKey();
		JwtBuilder b = Jwts.builder();
		b = b.setHeaderParam("serial", epk.getSerial()+"");
		//b = b.setPayload(UUID.randomUUID().toString());
		Map<String,Object> m = new HashMap<String, Object>();
		m.put("admin", true);
		m.put("userId", UUID.randomUUID().toString());
		b.addClaims(m);
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
		String s = b.compact();
		System.err.println(s);
		System.err.println(s.length());
	}

	public static void main(String[] args) throws NoSuchAlgorithmException {
		testShortToken();
	}
	
}
