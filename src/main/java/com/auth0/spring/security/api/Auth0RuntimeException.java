package com.auth0.spring.security.api;


public class Auth0RuntimeException extends RuntimeException {

	private static final long serialVersionUID = -7249102622891721159L;

	public Auth0RuntimeException(String message){
		super(message);
	}

	public Auth0RuntimeException(String message, Throwable cause){
		super(message, cause);
	}

	public Auth0RuntimeException(Throwable cause){
		super(cause);
	}

}
