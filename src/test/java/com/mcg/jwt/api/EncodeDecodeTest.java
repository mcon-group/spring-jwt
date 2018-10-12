package com.mcg.jwt.api;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import com.mcg.jwt.crypto.DefaultKeyProvider;
import com.mcg.jwt.example.User;
import com.mcg.jwt.example.UserTokenReader;
import com.mcg.jwt.example.UserTokenWriter;
import com.mcg.jwt.exception.TokenException;
import com.mcg.jwt.exception.TokenExpiredException;

public class EncodeDecodeTest {
	
	@Test
	public void testEncodeDecodeRSA() throws NoSuchAlgorithmException, TokenException {
		DefaultKeyProvider dkp = new DefaultKeyProvider();
		dkp.setAlgorithm("RSA");
		dkp.generateKeyPair();
		dkp.getPrivateKey();
		UserTokenWriter utw = new UserTokenWriter();
		utw.setPrivateKeyProvider(dkp);
		UserTokenReader utr = new UserTokenReader();
		utr.setPublicKeyProvider(dkp);
		
		User u = new User();
		u.setId("hund");
		u.setName("katze");
		List<String> x = new ArrayList<String>();
		x.add("a");
		x.add("b");
		x.add("c");
		
		u.setAuthorities(x);
		
		String s = utw.createToken(u, new Date(System.currentTimeMillis()+5000));
		System.err.println(s);
		User u2 = utr.readToken(s);
		System.err.println(u2);
		
		Assert.assertEquals(u.getId(), u2.getId());
		Assert.assertEquals(u.getName(), u2.getName());

	}
	

	@Test(expected=TokenExpiredException.class)
	public void testEncodeDecodeExpired() throws NoSuchAlgorithmException, InterruptedException, TokenException {
		DefaultKeyProvider dkp = new DefaultKeyProvider();
		dkp.setAlgorithm("RSA");
		dkp.generateKeyPair();
		UserTokenWriter utw = new UserTokenWriter();
		utw.setPrivateKeyProvider(dkp);
		UserTokenReader utr = new UserTokenReader();
		utr.setPublicKeyProvider(dkp);
		
		User u = new User();
		u.setId("hund");
		u.setName("katze");
		List<String> x = new ArrayList<String>();
		x.add("a");
		x.add("b");
		x.add("c");
		
		u.setAuthorities(x);
		
		String s = utw.createToken(u, new Date(System.currentTimeMillis()+100)); 
		Thread.sleep(2000);
		utr.readToken(s);
	}
	
	@Test
	public void testEncodeDecodeEC() throws NoSuchAlgorithmException, TokenException {
		DefaultKeyProvider dkp = new DefaultKeyProvider();
		dkp.setAlgorithm("EC");
		dkp.generateKeyPair();
		dkp.getPrivateKey();
		UserTokenWriter utw = new UserTokenWriter();
		utw.setPrivateKeyProvider(dkp);
		UserTokenReader utr = new UserTokenReader();
		utr.setPublicKeyProvider(dkp);
		
		User u = new User();
		u.setId("hund");
		u.setName("katze");
		List<String> x = new ArrayList<String>();
		x.add("a");
		x.add("b");
		x.add("c");
		
		u.setAuthorities(x);
		
		String s = utw.createToken(u, new Date(System.currentTimeMillis()+10000));
		User u2 = utr.readToken(s);
		Assert.assertEquals(u.getId(), u2.getId());
		Assert.assertEquals(u.getName(), u2.getName());

	}
	
	@Test(expected=NoSuchAlgorithmException.class)
	public void testEncodeDecodeRandom() throws NoSuchAlgorithmException, TokenException {
		DefaultKeyProvider dkp = new DefaultKeyProvider();
		dkp.setAlgorithm("HUND");
		dkp.generateKeyPair();
	}
	


}
