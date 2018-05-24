package cee.allianz.abs.catalina.authenticator.oidc;

import java.text.DateFormat;
import java.util.Date;

import org.json.JSONObject;

/**
 * OP token endpoint response.
 */
final class TokenEndpointResponse {

	/**
	 * Response HTTP status code.
	 */
	final int responseCode;

	/**
	 * Response date.
	 */
	final Date responseDate;

	/**
	 * Response body.
	 */
	final JSONObject responseBody;

	/**
	 * Create new object representing a response.
	 *
	 * @param responseCode
	 *            Response HTTP status code.
	 * @param responseDate
	 *            Response date.
	 * @param responseBody
	 *            Response body.
	 */
	TokenEndpointResponse(final int responseCode, final long responseDate, final JSONObject responseBody) {

		this.responseCode = responseCode;
		this.responseDate = new Date(responseDate != 0 ? responseDate : System.currentTimeMillis());
		this.responseBody = responseBody;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {

		return "status: " + this.responseCode + ", date: "
				+ DateFormat.getDateTimeInstance().format(this.responseDate) + ", body: " + this.responseBody;
	}
}