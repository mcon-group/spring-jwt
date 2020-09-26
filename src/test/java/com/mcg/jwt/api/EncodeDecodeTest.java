package com.mcg.jwt.api;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.util.Base64Utils;

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
		User u2 = utr.readToken(s);
		
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
	
	@Test
	public void repeatEncodeDecodeTest() throws NoSuchAlgorithmException, TokenException {
		for(int i=0;i < 100;i++) {
			try {
				System.err.println("repeating en- and decode: "+i);
				testEncodeDecodeEC();
				testEncodeDecodeRSA();
			} catch (Exception e) {
				throw e;
			}
		}
		
	}
	
	@Test(expected=NoSuchAlgorithmException.class)
	public void testEncodeDecodeRandom() throws NoSuchAlgorithmException, TokenException {
		DefaultKeyProvider dkp = new DefaultKeyProvider();
		dkp.setAlgorithm("HUND");
		dkp.generateKeyPair();
	}
	
	public static void main(String[] args) throws Exception {
		String PubKey= "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2sNRGKd0NvYaCXISCT5Fq+ImFsjQFsLqJemw6qmmXU2QI1DLq0MmmhcYWWDJeyrfRPNiFivvH2J5bWyNotPCDVXhd9zgIkp7efv7Ryy8vxwcX34L+GRBAKOlPU0NdH4/";
		String Data = "ZXlKelpYSnBZV3dpT2lJeE5UWTRPRGc1TWpNMk16TTJJaXdpWVd4bklqb2lSVk15TlRZaWZRLmV5SmxlSEFpT2pFMU5qZzRPRGt5TkRZc0ltNWhiV1VpT2lKcllYUjZaU0lzSW1sa0lqb2lhSFZ1WkNJc0ltRjFkR2h2Y21sMGFXVnpJanBiSW1FaUxDSmlJaXdpWXlKZGZR";
		String Sig = "MGQCMDA2XaOtkfK/ukG8DXcNMjl7EvaUNF46sOPM2WnFsdaY3iQ0I6W7wSVlC9uGpjTOvQIwGrHkYTfgPmwIyOSDuuFP5Fvc2ljtE++Gn17tpxd44WDvAsb7GiaBNsk8W8/Pybs3";
		
		KeyFactory kf = KeyFactory.getInstance("EC");

		// Decode the private key (read as a byte[] called 'buf').
		X509EncodedKeySpec ks = new X509EncodedKeySpec(Base64Utils.decodeFromString(PubKey));
		
		Signature s = Signature.getInstance("SHA256withECDSA");
		s.initVerify(kf.generatePublic(ks));
		s.update(Base64Utils.decodeFromString(Data));
		System.err.println(s.verify(Base64Utils.decodeFromString(Sig)));
		
	}
	
	


}
