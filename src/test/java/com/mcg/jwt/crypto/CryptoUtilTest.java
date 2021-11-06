package com.mcg.jwt.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.junit.Assert;
import org.junit.Test;

public class CryptoUtilTest {
	
	@Test
	public void testEncodingDecodingExpectSuccess() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(4096,new SecureRandom());
		KeyPair kp = kpg.generateKeyPair();

		{
			String s = CryptoUtil.formatPublicKey(kp.getPublic());
			PublicKey pubKey = CryptoUtil.getPublicKey(s);
			String s2 = CryptoUtil.formatPublicKey(pubKey);
			Assert.assertEquals(s, s2);
		}
		{
			String s = CryptoUtil.formatPrivateKey(kp.getPrivate());
			PrivateKey privKey = CryptoUtil.getPrivateKey(s);
			String s2 = CryptoUtil.formatPrivateKey(privKey);
			Assert.assertEquals(s, s2);
		}

	}

}
