package com.mcg.jwt.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtil {
	
	
	
	
	public static PrivateKey getPrivateKey(String encoded) {
		
		try {
			
			encoded = encoded.replaceAll("-----.*", "");
			encoded = encoded.replaceAll("\\n", "");
			encoded = encoded.trim();
			
			byte[] decoded = Base64.getDecoder().decode(encoded);
			
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
			
			for(String a : new String[] {"RSA","EC"}) {
				try {
					KeyFactory kf = KeyFactory.getInstance(a);		
					PrivateKey pk = kf.generatePrivate(spec);
					return pk;
				} catch (Exception e) {
				}
			}
			
			throw new RuntimeException("unreadable private key");

		} catch (Exception e) {
			throw new RuntimeException("error reading private key", e);
		}
		
		
	}

	public static PublicKey getPublicKey(String encoded) {
		
		try {
			
			encoded = encoded.replaceAll("-----.*", "");
			encoded = encoded.replaceAll("\\n", "");
			encoded = encoded.trim();
			
			byte[] decoded = Base64.getDecoder().decode(encoded);
			
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			
			for(String a : new String[] {"RSA","EC"}) {
				try {
					KeyFactory kf = KeyFactory.getInstance(a);		
					PublicKey pk = kf.generatePublic(spec);
					return pk;
				} catch (Exception e) {
				}
			}
			
			throw new RuntimeException("unreadable public key");

		} catch (Exception e) {
			throw new RuntimeException("error reading public key", e);
		}
		
	}

	public static String formatPublicKey(PublicKey key) {
		StringBuffer sb = new StringBuffer();
		sb.append("-----BEGIN PUBLIC KEY-----\n");
		sb.append(Base64.getEncoder().encodeToString(key.getEncoded())+"\n");
		sb.append("-----END PUBLIC KEY-----\n");
		return sb.toString();
	}
	
	public static String formatPrivateKey(PrivateKey key) {
		StringBuffer sb = new StringBuffer();
		sb.append("-----BEGIN PRIVATE KEY-----\n");
		sb.append(Base64.getEncoder().encodeToString(key.getEncoded())+"\n");
		sb.append("-----END PRIVATE KEY-----\n");
		return sb.toString();
	}
	
}
