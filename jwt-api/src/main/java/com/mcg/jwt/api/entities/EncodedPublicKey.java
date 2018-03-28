package com.mcg.jwt.api.entities;

import java.security.PublicKey;

import com.fasterxml.jackson.annotation.JsonIgnore;

public interface EncodedPublicKey {

	PublicKey getPublicKey();

	String getAlgorithm();

	long getSerial();

}
