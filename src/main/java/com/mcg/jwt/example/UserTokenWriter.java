package com.mcg.jwt.example;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.mcg.jwt.TokenReader;
import com.mcg.jwt.TokenWriter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;

public class UserTokenWriter extends TokenWriter<User> {

	@Override
	public Map<String,Object> map(User in) {
		Map<String,Object> claims = new HashMap<String, Object>();
		claims.put("id", in.getId());
		claims.put("name", in.getName());
		claims.put("authorities", in.getAuthorities());
		return claims;
	}

}
