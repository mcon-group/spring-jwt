package com.mcg.jwt.api.example;

import java.util.List;
import java.util.Map;

import com.mcg.jwt.api.TokenReader;

public class UserTokenReader extends TokenReader<User> {

	@Override
	public User unmap(Map<String,Object> claims) {
		User user = new User();
		user.setId((String)claims.get("id"));
		user.setName((String)claims.get("name"));
		user.setAuthorities((List<String>)claims.get("authorities"));
		return user;
	}

}
