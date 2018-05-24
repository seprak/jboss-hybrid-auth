package cee.allianz.abs.catalina.authenticator.oidc;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.tomcat.util.buf.HexUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.jboss.logging.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import cee.allianz.abs.catalina.authenticator.IDPAuthenticator;
import static cee.allianz.abs.catalina.authenticator.oidc.OIDCAuthenticatorConstants.*;

public class BaseOpenIDConnectAuthenticator implements IDPAuthenticator {
	
	private static final Logger log = Logger.getLogger(BaseOpenIDConnectAuthenticator.class);


	/**
	 * Virtual host base URI.
	 */
	protected String hostBaseURI;

	/**
	 * Providers configuration.
	 */
	protected String providers;

	/**
	 * Name of the claim in the ID Token used as the username in the users realm.
	 * Can be overridden for specific OPs.
	 */
	protected String usernameClaim = "email";

	/**
	 * Space separated list of scopes to add to "openid" scope in the authorization
	 * endpoint request. Can be overridden for specific OPs.
	 */
	protected String additionalScopes;

	/**
	 * Tells if the form-based authentication is disabled.
	 */
	protected boolean noForm = false;

	/**
	 * HTTP connect timeout for OP endpoints.
	 */
	protected int httpConnectTimeout = 5000;

	/**
	 * HTTP read timeout for OP endpoints.
	 */
	protected int httpReadTimeout = 5000;

	/**
	 * Secure random number generator.
	 */
	private final SecureRandom rand = new SecureRandom();

	/**
	 * Configured OpenID Connect Provider descriptors.
	 */
	private List<OPDescriptor> opDescs;

	/**
	 * OpenID Connect Provider configurations provider.
	 */
	private OPConfigurationsProvider ops;

	/**
	 * Get virtual host base URI property.
	 *
	 * @return Host base URI.
	 */
	public String getHostBaseURI() {

		return this.hostBaseURI;
	}

	/**
	 * Set virtual host base URI property. The URI is used when constructing
	 * callback URLs for the web-application. If not set, the authenticator will
	 * attempt to construct it using the requests it receives.
	 *
	 * @param hostBaseURI
	 *            Host base URI. Must not end with a "/". Should be an HTTPS URI.
	 */
	public void setHostBaseURI(final String hostBaseURI) {

		this.hostBaseURI = hostBaseURI;
	}

	/**
	 * Get providers configuration.
	 *
	 * @return The providers configuration
	 */
	public String getProviders() {

		return this.providers;
	}

	/**
	 * Set providers configuration.
	 *
	 * @param providers
	 *            The providers configuration, which is a JSON-like array of
	 *            descriptors, one for each configured provider. Unlike standard
	 *            JSON, the syntax does not use double quotes around the property
	 *            names and values (to make it XML attribute value friendly). The
	 *            value can be surrounded with single quotes if it contains commas,
	 *            curly braces or whitespace.
	 */
	public void setProviders(final String providers) {

		this.providers = providers;
	}

	/**
	 * Get name of the claim in the ID Token used as the username.
	 *
	 * @return The claim name.
	 */
	public String getUsernameClaim() {

		return this.usernameClaim;
	}

	/**
	 * Set name of the claim in the ID Token used as the username in the users
	 * realm. The default is "sub".
	 *
	 * @param usernameClaim
	 *            The claim name.
	 */
	public void setUsernameClaim(final String usernameClaim) {

		this.usernameClaim = usernameClaim;
	}

	/**
	 * Get additional scopes for the authorization endpoint.
	 *
	 * @return The additional scopes.
	 */
	public String getAdditionalScopes() {

		return this.additionalScopes;
	}

	/**
	 * Set additional scopes for the authorization endpoint. The scopes are added to
	 * the required "openid" scope, which is always included.
	 *
	 * @param additionalScopes
	 *            The additional scopes as a space separated list.
	 */
	public void setAdditionalScopes(final String additionalScopes) {

		this.additionalScopes = additionalScopes;
	}

	/**
	 * Tell if form-based authentication is disabled.
	 *
	 * @return {@code true} if disabled.
	 */
	public boolean isNoForm() {

		return this.noForm;
	}

	/**
	 * Set flag that tells if the form-based authentication should be disabled.
	 *
	 * @param noForm
	 *            {@code true} to disabled form-based authentication.
	 */
	public void setNoForm(final boolean noForm) {

		this.noForm = noForm;
	}

	/**
	 * Get HTTP connect timeout used for server-to-server communication with the
	 * OpenID Connect provider.
	 *
	 * @return Timeout in milliseconds.
	 */
	public int getHttpConnectTimeout() {

		return this.httpConnectTimeout;
	}

	/**
	 * Set HTTP connect timeout used for server-to-server communication with the
	 * OpenID Connect provider. The default is 5000.
	 *
	 * @param httpConnectTimeout
	 *            Timeout in milliseconds.
	 *
	 * @see URLConnection#setConnectTimeout(int)
	 */
	public void setHttpConnectTimeout(final int httpConnectTimeout) {

		this.httpConnectTimeout = httpConnectTimeout;
	}

	/**
	 * Get HTTP read timeout used for server-to-server communication with the OpenID
	 * Connect provider.
	 *
	 * @return Timeout in milliseconds.
	 */
	public int getHttpReadTimeout() {

		return this.httpReadTimeout;
	}

	/**
	 * Set HTTP read timeout used for server-to-server communication with the OpenID
	 * Connect provider. The default is 5000.
	 *
	 * @param httpReadTimeout
	 *            Timeout in milliseconds.
	 *
	 * @see URLConnection#setReadTimeout(int)
	 */
	public void setHttpReadTimeout(final int httpReadTimeout) {

		this.httpReadTimeout = httpReadTimeout;
	}

	@Override
	public synchronized void init(String providers) throws Exception {

		// verify that providers are configured
		if (providers == null)
			throw new LifecycleException("OpenIDConnectAuthenticator requires" + " \"providers\" property.");

		// parse provider definitions and create the configurations provider
		final String providersConf = providers.trim();
		final StringBuffer providersConfJSONBuf = new StringBuffer();
		final Matcher m = OP_CONF_LINE_PATTERN.matcher(providersConf);
		while (m.find()) {
			m.appendReplacement(providersConfJSONBuf, Matcher.quoteReplacement(
					"\"" + m.group(1) + "\": \"" + (m.group(2) != null ? m.group(2) : m.group(3)) + "\""));
		}
		m.appendTail(providersConfJSONBuf);
		final String providersConfJSON = providersConfJSONBuf.toString();
		try {
			log.debug("parsing configuration JSON: " + providersConfJSON);
			final JSONArray opDefs = new JSONArray(new JSONTokener(new StringReader(providersConfJSON)));
			final int numOPs = opDefs.length();
			this.opDescs = new ArrayList<>(numOPs);
			for (int i = 0; i < numOPs; i++) {
				final Object opDef = opDefs.opt(i);
				if ((opDef == null) || !(opDef instanceof JSONObject))
					throw new LifecycleException("Expected an object at" + " OpenIDConnectAuthenticator \"providers\""
							+ " array element " + i + ".");
				this.opDescs.add(new OPDescriptor((JSONObject) opDef, this.usernameClaim, this.additionalScopes));
			}
		} catch (JSONException e) {
			throw new LifecycleException("OpenIDConnectAuthenticator could" + " not parse \"providers\" property.", e);
		}

		this.ops = new OPConfigurationsProvider(this.opDescs);

		// preload provider configurations and detect any errors
		try {
			for (final OPDescriptor opDesc : this.opDescs)
				this.ops.getOPConfiguration(opDesc.getIssuer());
		} catch (final IOException | JSONException e) {
			throw new LifecycleException(
					"OpenIDConnectAuthenticator could not" + " load OpenID Connect Provider configuration.", e);
		}

	}

	/**
	 * Add request attributes for the login or the login error page.
	 *
	 * @param request
	 *            The request.
	 *
	 * @throws IOException
	 *             If an I/O error happens.
	 */
	public void addRequestAttributes(final Request request) throws IOException {

		// generate state value and save it in the session
		final byte[] stateBytes = new byte[16];
		this.rand.nextBytes(stateBytes);
		final String state = HexUtils.convert(stateBytes);
		request.getSessionInternal(true).setNote(SESS_STATE_NOTE, state);

		// add OP authorization endpoints to the request for the login page
		final List<AuthEndpointDesc> authEndpoints = new ArrayList<>();
		final StringBuilder buf = new StringBuilder(128);
		for (int i = 0; i < this.opDescs.size(); i++) {
			final OPDescriptor opDesc = this.opDescs.get(i);

			// get the OP configuration
			final String issuer = opDesc.getIssuer();
			final OPConfiguration opConfig = this.ops.getOPConfiguration(issuer);

			// construct the authorization endpoint URL
			buf.setLength(0);
			buf.append(opConfig.getAuthorizationEndpoint());
			buf.append("?scope=openid email");
			final String extraScopes = opDesc.getAdditionalScopes();
			if (extraScopes != null)
				buf.append(URLEncoder.encode(" " + extraScopes, UTF8.name()));
			buf.append("&response_type=code");
			buf.append("&client_id=").append(URLEncoder.encode(opDesc.getClientId(), UTF8.name()));
			buf.append("&redirect_uri=")
					.append(URLEncoder.encode(this.getBaseURL(request) + Constants.FORM_ACTION, UTF8.name()));
			buf.append("&state=").append(i).append('Z').append(state);
			final String addlParams = opDesc.getExtraAuthEndpointParams();
			if (addlParams != null)
				buf.append('&').append(addlParams);

			// add the URL to the map
			authEndpoints.add(new AuthEndpointDesc(opDesc.getName(), issuer, buf.toString()));
		}
		request.setAttribute(AUTHEPS_ATT, authEndpoints);

	}

	public Principal processAuthentication(final Session session, final Request request) throws IOException {

		log.debug("Authenticating user using OpenID Connect authentication response");

		// parse the state
		final String stateParam = request.getParameter("state");
		if (stateParam == null) {
			log.debug("no state in the authentication response");
			return null;
		}
		final Matcher m = STATE_PATTERN.matcher(stateParam);
		if (!m.find()) {
			log.debug("Invalid state value in the authentication response");
			return null;
		}
		final int opInd = Integer.parseInt(m.group(1));
		final String state = m.group(2);

		// get OP descriptor from the state
		if (opInd >= this.opDescs.size()) {
			log.debug("authentication response state contains invalid OP index");
			return null;
		}
		final OPDescriptor opDesc = this.opDescs.get(opInd);
		final String issuer = opDesc.getIssuer();
		log.debug("processing authentication response from " + issuer);

		// match the session id from the state
		final String sessionState = (String) session.getNote(SESS_STATE_NOTE);
		session.removeNote(SESS_STATE_NOTE);
		if (!state.equals(sessionState)) {
			log.debug("authentication response state does not match the session id");
			return null;
		}

		// check if error response
		final String errorCode = request.getParameter("error");
		if (errorCode != null) {
			final AuthErrorDesc authError = new AuthErrorDesc(request);
			log.debug("authentication error response: " + authError.getCode());
			request.setAttribute(AUTHERROR_ATT, authError);
			return null;
		}

		// get the authorization code
		final String authCode = request.getParameter("code");
		if (authCode == null) {
			log.debug("no authorization code in the authentication response");
			return null;
		}

		// call the token endpoint, check if error and get the ID token
		final TokenEndpointResponse tokenResponse = this.callTokenEndpoint(opDesc, authCode, request);
		final String tokenErrorCode = tokenResponse.responseBody.optString("error");
		if ((tokenResponse.responseCode != HttpURLConnection.HTTP_OK) || (tokenErrorCode.length() > 0)) {
			final AuthErrorDesc authError = new AuthErrorDesc(tokenResponse.responseBody);
			log.debug("token error response: " + authError.getCode());
			request.setAttribute(AUTHERROR_ATT, authError);
			return null;
		}

		// create the authorization object
		final Authorization authorization = new Authorization(issuer, tokenResponse.responseDate,
				tokenResponse.responseBody);

		// decode the ID token
		final String[] idTokenParts = authorization.getIdToken().split("\\.");
		final JSONObject idTokenHeader = new JSONObject(
				new JSONTokener(new StringReader(new String(Base64.decodeBase64(idTokenParts[0]), UTF8))));
		final JSONObject idTokenPayload = new JSONObject(
				new JSONTokener(new StringReader(new String(Base64.decodeBase64(idTokenParts[1]), UTF8))));
		final byte[] idTokenSignature = Base64.decodeBase64(idTokenParts[2]);
		log.debug("decoded ID token:" + "\n    header:    " + idTokenHeader + "\n    payload:   " + idTokenPayload
				+ "\n    signature: " + Arrays.toString(idTokenSignature));

		// validate issuer match
		if (!issuer.equals(idTokenPayload.getString("iss"))) {
			log.debug("the ID token issuer does not match");
			return null;
		}

		// validate audience match
		final Object audValue = idTokenPayload.get("aud");
		boolean audMatch = false;
		if (audValue instanceof JSONArray) {
			final JSONArray auds = (JSONArray) audValue;
			for (int n = auds.length() - 1; n >= 0; n--) {
				if (opDesc.getClientId().equals(auds.get(n))) {
					audMatch = true;
					break;
				}
			}
		} else {
			audMatch = opDesc.getClientId().equals(audValue);
		}
		if (!audMatch) {
			log.debug("the ID token audience does not match");
			return null;
		}

		// validate authorized party
		if ((audValue instanceof JSONArray) && idTokenPayload.has("azp")) {
			if (!opDesc.getClientId().equals(idTokenPayload.get("azp"))) {
				log.debug("the ID token authorized party does not match");
				return null;
			}
		}

		// validate token expiration
		if (!idTokenPayload.has("exp") || (idTokenPayload.getLong("exp") * 1000L) <= System.currentTimeMillis()) {
			log.debug("the ID token expired or no expiration time");
			return null;
		}

		// validate signature
		if (!this.isSignatureValid(opDesc, idTokenHeader, idTokenParts[0] + '.' + idTokenParts[1], idTokenSignature)) {
			log.debug("invalid signature");
			return null;
		}

		// get username from the ID token
		JSONObject usernameClaimContainer = idTokenPayload;
		final String[] usernameClaimParts = opDesc.getUsernameClaimParts();
		for (int i = 0; i < usernameClaimParts.length - 1; i++) {
			final Object v = usernameClaimContainer.opt(usernameClaimParts[i]);
			if ((v == null) || !(v instanceof JSONObject)) {
				log.debug("the ID token does not contain the \"" + opDesc.getUsernameClaim()
							+ "\" claim used as the username claim");
				return null;
			}
			usernameClaimContainer = (JSONObject) v;
		}
		final String username = usernameClaimContainer.optString(usernameClaimParts[usernameClaimParts.length - 1],
				null);
		if (username == null) {
			log.debug("the ID token does not contain the \"" + opDesc.getUsernameClaim()
						+ "\" claim used as the username claim");
			return null;
		}

		// authenticate the user in the realm
		log.debug("authenticating user \"" + username + "\"");

		// TODO create principal
		final Principal principal = new GenericPrincipal(null, username, null, Arrays.asList("user")); // this.context.getRealm().authenticate(username);

		// save authentication info in the session
		session.setNote(Constants.SESS_USERNAME_NOTE, principal.getName());
		session.setNote(SESS_OIDC_AUTH_NOTE, authorization);

		// save authorization in the session for the application
		session.getSession().setAttribute(AUTHORIZATION_ATT, authorization);

		// return the principal
		return principal;
	}

	/**
	 * Check if the JWT signature is valid.
	 *
	 * @param opDesc
	 *            OP descriptor.
	 * @param header
	 *            Decoded JWT header.
	 * @param data
	 *            The JWT data (encoded header and payload).
	 * @param signature
	 *            The signature from the JWT to test.
	 *
	 * @return {@code true} if valid.
	 *
	 * @throws IOException
	 *             If an I/O error happens loading necessary data.
	 */
	protected boolean isSignatureValid(final OPDescriptor opDesc, final JSONObject header, final String data,
			final byte[] signature) throws IOException {

		try {

			final String sigAlg = header.optString("alg");

			switch (sigAlg) {

			case "RS256":

				final Signature sig = Signature.getInstance("SHA256withRSA");
				sig.initVerify(
						this.ops.getOPConfiguration(opDesc.getIssuer()).getJWKSet().getKey(header.getString("kid")));
				sig.update(data.getBytes("ASCII"));

				return sig.verify(signature);

			case "HS256":

				if (opDesc.getClientSecret() == null) {
					log.warn("client secret required for HS256 signature" + " algorithm is not configured, reporting"
							+ " signature invalid");
					return false;
				}

				final Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(new SecretKeySpec(Base64.decodeBase64(opDesc.getClientSecret()), "HmacSHA256"));
				mac.update(data.getBytes("ASCII"));
				final byte[] genSig = mac.doFinal();

				return Arrays.equals(genSig, signature);

			default:

				log.warn("unsupported token signature algorithm \"" + sigAlg + "\", skipping signature verification");

				return true;
			}

		} catch (final NoSuchAlgorithmException | SignatureException | InvalidKeyException
				| UnsupportedEncodingException e) {
			throw new RuntimeException("Platform lacks signature algorithm support.", e);
		}
	}

	/**
	 * Call the IDP's token end-point and exchange the authorization code.
	 *
	 */
	protected TokenEndpointResponse callTokenEndpoint(final OPDescriptor opDesc, final String authCode,
			final Request request) throws IOException {

		// get the OP configuration
		final OPConfiguration opConfig = this.ops.getOPConfiguration(opDesc.getIssuer());
		final URL tokenEndpointURL = new URL(opConfig.getTokenEndpoint());

		// build POST body
		final StringBuilder buf = new StringBuilder(256);
		buf.append("grant_type=authorization_code");
		buf.append("&code=").append(URLEncoder.encode(authCode, UTF8.name()));
		buf.append("&redirect_uri=")
				.append(URLEncoder.encode(this.getBaseURL(request) + Constants.FORM_ACTION, UTF8.name()));
		buf.append("&client_id=").append(URLEncoder.encode(opDesc.getClientId(), UTF8.name()));

		// configure connection
		final HttpURLConnection con = (HttpURLConnection) tokenEndpointURL.openConnection();
		con.setConnectTimeout(this.httpConnectTimeout);
		con.setReadTimeout(this.httpReadTimeout);
		con.setDoOutput(true);
		con.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		con.addRequestProperty("Accept", "application/json");
		con.setInstanceFollowRedirects(false);

		// configure authentication
		switch (opDesc.getTokenEndpointAuthMethod()) {
		case CLIENT_SECRET_BASIC:
			con.addRequestProperty("Authorization", "Basic " + Base64
					.encodeBase64String((opDesc.getClientId() + ":" + opDesc.getClientSecret()).getBytes(UTF8)));
			break;
		case CLIENT_SECRET_POST:
			buf.append("&client_secret=").append(URLEncoder.encode(opDesc.getClientSecret(), UTF8.name()));
			break;
		default:
		}

		// finish POST body and log the call
		final String postBody = buf.toString();
		log.debug("calling token endpoint at " + tokenEndpointURL + " with: " + postBody);

		// send POST and read response
		JSONObject responseBody;
		try (final OutputStream out = con.getOutputStream()) {
			out.write(postBody.getBytes(UTF8.name()));
			out.flush();
			try (final Reader in = new InputStreamReader(con.getInputStream(), UTF8)) {
				responseBody = new JSONObject(new JSONTokener(in));
			} catch (final IOException e) {
				final InputStream errorStream = con.getErrorStream();
				if (errorStream == null)
					throw e;
				try (final Reader in = new InputStreamReader(errorStream, UTF8)) {
					responseBody = new JSONObject(new JSONTokener(in));
				}
			}
		}

		// create response object
		final TokenEndpointResponse response = new TokenEndpointResponse(con.getResponseCode(), con.getDate(),
				responseBody);

		// log the response
		log.debug("received response: " + response.toString());

		// return the response
		return response;
	}

	/**
	 * Get web-application base URL (either from the {@code hostBaseURI}
	 * authenticator property or auto-detected from the request).
	 *
	 * @param request
	 *            The request.
	 *
	 * @return Base URL.
	 */
	protected String getBaseURL(final Request request) {

		if (this.hostBaseURI != null)
			return this.hostBaseURI + request.getContextPath();

		final StringBuilder baseURLBuf = new StringBuilder(64);
		// TODO should always do HTTPS
		baseURLBuf.append("http://").append(request.getServerName());
		final int port = request.getServerPort();
		if (port != 443)
			baseURLBuf.append(':').append(port);
		baseURLBuf.append(request.getContextPath());

		return baseURLBuf.toString();
	}

	@Override
	public boolean isApplicable(HttpServletRequest request) {
		return ((request.getParameter("code") != null) || (request.getParameter("error") != null));
	}

	@Override
	public void removeNotes(Session session) {
		session.removeNote(SESS_OIDC_AUTH_NOTE);
	}
}
