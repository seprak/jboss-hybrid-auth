package cee.allianz.abs.catalina.authenticator.oidc;

import java.nio.charset.Charset;
import java.util.regex.Pattern;

public interface OIDCAuthenticatorConstants {
	/**
	 * Name of request attribute made available to the login page that maps
	 * configured OP issuer IDs to the corresponding authorization endpoint URLs.
	 */
	public static final String AUTHEPS_ATT = "cee.allianz.abs.oidc.authEndpoints";

	/**
	 * Name of request attribute made available on the login error page that
	 * contains the error descriptor.
	 */
	public static final String AUTHERROR_ATT = "cee.allianz.abs.oidc.error";

	/**
	 * Name of session attribute used to store the {@link Authorization} object.
	 */
	public static final String AUTHORIZATION_ATT = "cee.allianz.abs.oidc.authorization";

	/**
	 * UTF-8 charset.
	 */
	public static final Charset UTF8 = Charset.forName("UTF-8");

	/**
	 * Name of the HTTP session note used to store the {@link Authorization} object.
	 */
	public static final String SESS_OIDC_AUTH_NOTE = "cee.allianz.abs.catalina.session.AUTHORIZATION";

	/**
	 * Name of the HTTP session note used to store the state value.
	 */
	public static final String SESS_STATE_NOTE = "cee.allianz.abs.catalina.session.STATE";

	/**
	 * Pattern for the state parameter.
	 */
	public static final Pattern STATE_PATTERN = Pattern.compile("^(\\d+)Z(.+)");

	/**
	 * Pattern used to parse providers configuration and convert it into JSON.
	 */
	public static final Pattern OP_CONF_LINE_PATTERN = Pattern.compile("(\\w+)\\s*:\\s*(?:'([^']*)'|([^\\s,{}]+))");


}
