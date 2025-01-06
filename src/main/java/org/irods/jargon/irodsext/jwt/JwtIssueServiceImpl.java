/**
 * 
 */
package org.irods.jargon.irodsext.jwt;

import java.security.Key;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * @author Mike Conway - NIEHS
 *
 */
public class JwtIssueServiceImpl extends AbstractJwtIssueService {

	public static final Logger log = LogManager.getLogger(JwtIssueServiceImpl.class);

	private final JwtServiceConfig jwtServiceConfig;
	private final Key myKey;

	/**
	 * Constructor with configs
	 * 
	 * @param jwtServiceConfig {@link JwtServiceConfig}
	 */
	public JwtIssueServiceImpl(final JwtServiceConfig jwtServiceConfig) {
		if (jwtServiceConfig == null) {
			throw new IllegalArgumentException("null jwtServiceConfig");
		}

		this.jwtServiceConfig = jwtServiceConfig;
		myKey = Keys.hmacShaKeyFor(jwtServiceConfig.getSecret().getBytes());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.irods.jargon.irodsext.jwt.AbstractJwtIssueService#issueJwtToken(java.lang.String)
	 */
	@Override
	public String issueJwtToken(final String subject) {
		log.info("issueJwtToken()");

		if (subject == null || subject.isEmpty()) {
			throw new IllegalArgumentException("null or empty subject");
		}

		String signedJwt = Jwts.builder().setSubject(subject).setIssuer(jwtServiceConfig.getIssuer())
				.setIssuedAt(new Date()).signWith(myKey).compact();
		return signedJwt;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.irods.jargon.irodsext.jwt.AbstractJwtIssueService#decodeJwtToken(java.lang.
	 * String)
	 */
	@Override
	public Jws<Claims> decodeJwtToken(final String token) {
		log.info("decodeJwtToken()");

		if (token == null || token.isEmpty()) {
			throw new IllegalArgumentException("null or empty token");
		}

		Jws<Claims> claims = Jwts.parser().setSigningKey(myKey).parseClaimsJws(token);
		return claims;

	}

}
