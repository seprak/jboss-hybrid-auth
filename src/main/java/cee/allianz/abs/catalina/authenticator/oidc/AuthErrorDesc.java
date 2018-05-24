package cee.allianz.abs.catalina.authenticator.oidc;

import org.apache.catalina.connector.Request;
import org.json.JSONObject;


/**
 * Authentication error descriptor for the error page.
 */
public final class AuthErrorDesc {

	/**
	 * Error code.
	 */
	final String code;

	/**
	 * Optional error description.
	 */
	final String description;

	/**
	 * Optional URI of the page with the error information.
	 */
	final String infoPageURI;

	/**
	 * Create new descriptor using request parameters.
	 *
	 * @param request
	 *            The request representing the error response.
	 */
	AuthErrorDesc(final Request request) {

		this.code = request.getParameter("error");
		this.description = request.getParameter("error_description");
		this.infoPageURI = request.getParameter("error_uri");
	}

	/**
	 * Create new descriptor using endpoint error response JSON.
	 *
	 * @param error
	 *            The error response JSON.
	 */
	AuthErrorDesc(final JSONObject error) {

		this.code = error.getString("error");
		this.description = error.optString("error_description", null);
		this.infoPageURI = error.optString("error_uri", null);
	}

	/**
	 * Get error code.
	 *
	 * @return The code.
	 */
	public String getCode() {

		return this.code;
	}

	/**
	 * Get optional error description.
	 *
	 * @return The description, or {@code null}.
	 */
	public String getDescription() {

		return this.description;
	}

	/**
	 * Get optional URI of the page containing the error information.
	 *
	 * @return The page URI, or {@code null}.
	 */
	public String getInfoPageURI() {

		return this.infoPageURI;
	}
}