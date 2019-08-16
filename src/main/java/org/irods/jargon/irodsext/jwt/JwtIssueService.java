package org.irods.jargon.irodsext.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * Interface for a service to (with proper configuration) issue JWTs for use
 * with plug-in microservices
 * 
 * @author Mike Conway - NIEHS
 *
 */
public interface JwtIssueService {

	/**
	 * Given a subject, issue a proper JWT that can be understood by Metalnx plugins
	 * 
	 * @param subject {@code String} with the subject for the JWT claim
	 * @return {@code String} with the JWT token
	 */
	String issueJwtToken(String subject);

	/**
	 * Given a JWT token, return the decoded claims
	 * 
	 * @param token {@code String} with the JWT token
	 * @return {@link Jws} with the associated claims
	 */
	Jws<Claims> decodeJwtToken(String token);

}