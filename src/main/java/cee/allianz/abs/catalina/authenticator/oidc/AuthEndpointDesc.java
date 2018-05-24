package cee.allianz.abs.catalina.authenticator.oidc;

/**
 * Authorization endpoint descriptor for the login page.
 */
public final class AuthEndpointDesc {

	/**
	 * OP name.
	 */
	private final String name;

	/**
	 * Issuer ID.
	 */
	private final String issuer;

	/**
	 * Endpoint URL.
	 */
	private final String url;

	/**
	 * Create new descriptor.
	 *
	 * @param name
	 *            OP name.
	 * @param issuer
	 *            Issuer ID.
	 * @param url
	 *            Endpoint URL.
	 */
	AuthEndpointDesc(final String name, final String issuer, final String url) {

		this.name = name;
		this.issuer = issuer;
		this.url = url;
	}

	/**
	 * Get OP name.
	 *
	 * @return The OP name.
	 */
	public String getName() {

		return this.name;
	}

	/**
	 * Get issuer ID.
	 *
	 * @return The issuer ID.
	 */
	public String getIssuer() {

		return this.issuer;
	}

	/**
	 * Get endpoint URL.
	 *
	 * @return The URL.
	 */
	public String getUrl() {

		return this.url;
	}
}