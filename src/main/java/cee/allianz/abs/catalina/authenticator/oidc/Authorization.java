package cee.allianz.abs.catalina.authenticator.oidc;

import java.text.DateFormat;
import java.util.Date;

import org.json.JSONObject;


/**
 * The successful authorization information derived from the token endpoint
 * response.
 */
public final class Authorization {

	/**
	 * Issuer ID.
	 */
	private final String issuer;

	/**
	 * Timestamp when the authorization was issued.
	 */
	private final Date issuedAt;

	/**
	 * Access token.
	 */
	private final String accessToken;

	/**
	 * Token type.
	 */
	private final String tokenType;

	/**
	 * Seconds to the authorization (access token) expiration.
	 */
	private final int expiresIn;

	/**
	 * Optional refresh token.
	 */
	private final String refreshToken;

	/**
	 * Optional scope.
	 */
	private final String scope;

	/**
	 * ID token.
	 */
	private final String idToken;

	/**
	 * Create new authorization descriptor.
	 *
	 * @param issuer
	 *            Issuer ID.
	 * @param issuedAt
	 *            Timestamp when the authorization was issued.
	 * @param tokenResponse
	 *            Successful token endpoint response document.
	 */
	Authorization(final String issuer, final Date issuedAt, final JSONObject tokenResponse) {

		this.issuer = issuer;
		this.issuedAt = issuedAt;

		this.accessToken = tokenResponse.getString("access_token");
		this.tokenType = tokenResponse.getString("token_type");
		this.expiresIn = tokenResponse.optInt("expires_in", -1);
		this.refreshToken = tokenResponse.optString("refresh_token", null);
		this.scope = tokenResponse.optString("scope", null);
		this.idToken = tokenResponse.getString("id_token");
	}

	/**
	 * Get Issuer Identifier.
	 *
	 * @return The issuer ID.
	 */
	public String getIssuer() {

		return this.issuer;
	}

	/**
	 * Get timestamp when the authorization was issued.
	 *
	 * @return The timestamp (milliseconds).
	 */
	public Date getIssuedAt() {

		return this.issuedAt;
	}

	/**
	 * Get access token.
	 *
	 * @return The access token.
	 */
	public String getAccessToken() {

		return this.accessToken;
	}

	/**
	 * Get access token type (e.g. "Bearer").
	 *
	 * @return Access token type.
	 */
	public String getTokenType() {

		return this.tokenType;
	}

	/**
	 * Get access token expiration.
	 *
	 * @return Seconds after which the authorization (the access token) expires, or
	 *         -1 if unspecified.
	 */
	public int getExpiresIn() {

		return this.expiresIn;
	}

	/**
	 * Get optional refresh token.
	 *
	 * @return The refresh token, or {@code null} if none.
	 */
	public String getRefreshToken() {

		return this.refreshToken;
	}

	/**
	 * Get optional scope.
	 *
	 * @return The scope, or {@code null} if none.
	 */
	public String getScope() {

		return this.scope;
	}

	/**
	 * Get ID token.
	 *
	 * @return The ID token.
	 */
	public String getIdToken() {

		return this.idToken;
	}

	@Override
	public String toString() {

		final StringBuilder buf = new StringBuilder(1024);
		buf.append("Authorization issued at ").append(DateFormat.getDateTimeInstance().format(this.issuedAt))
				.append(" by ").append(this.issuer).append(":");
		buf.append("\n  accessToken:  ").append(this.accessToken);
		buf.append("\n  tokenType:    ").append(this.tokenType);
		buf.append("\n  expiresIn:    ").append(this.expiresIn).append(" seconds");
		buf.append("\n  refreshToken: ").append(this.refreshToken);
		buf.append("\n  scope:        ").append(this.scope);
		buf.append("\n  idToken:      ").append(this.idToken);

		return buf.toString();
	}
}