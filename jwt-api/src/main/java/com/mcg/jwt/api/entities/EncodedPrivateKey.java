package com.mcg.jwt.api.entities;

import java.security.PrivateKey;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnore;

public interface EncodedPrivateKey {

	Date getNotAfter();

	PrivateKey getPrivateKey();

	String getAlgorithm();

	long getSerial();

}
