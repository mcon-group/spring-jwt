package com.mcg.jwt.entities;

import java.security.PublicKey;

import com.fasterxml.jackson.annotation.JsonIgnore;

public interface EncodedPublicKey {

	PublicKey getPublicKey();

	String getAlgorithm();

	long getSerial();

}
