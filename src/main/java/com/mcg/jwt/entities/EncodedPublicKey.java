package com.mcg.jwt.entities;

import java.security.PublicKey;
import java.util.Date;

public interface EncodedPublicKey {

	PublicKey getPublicKey();

	void setPublicKey(PublicKey publicKey);

	String getAlgorithm();

	long getSerial();

	void setIssued(Date issued);

	Date getIssued();

	void setNotAfter(Date notAfter);

	Date getNotAfter();

	void setAlgorithm(String algorithm);

	void setSerial(long serial);

	void setKey(String key);

	String getKey();


}
