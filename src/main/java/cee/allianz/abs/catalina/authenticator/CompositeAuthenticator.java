package cee.allianz.abs.catalina.authenticator;

import static org.jboss.web.CatalinaMessages.MESSAGES;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.jboss.logging.Logger;
import org.jboss.web.CatalinaLogger;

import cee.allianz.abs.catalina.authenticator.oidc.BaseOpenIDConnectAuthenticator;

/**
 * Base authenticator implementation for composite FORM/IDP authentication
 *
 * @author vsprk
 */
public abstract class CompositeAuthenticator extends FormAuthenticator {

	private static final Logger log = Logger.getLogger(CompositeAuthenticator.class);
	
	// Added from valve parameter, but should be obtained from RAP registry
	protected String providers;
	
	private List<IDPAuthenticator> idpAuthenticators = new ArrayList<>();

	@Override
	public void start() throws LifecycleException {

		// TODO add IDP impl. automatic discovery
		BaseOpenIDConnectAuthenticator oidcAuth = new BaseOpenIDConnectAuthenticator();
		try {
			oidcAuth.init(providers);
			idpAuthenticators.add(oidcAuth);
		} catch (Exception e) {
			throw new LifecycleException(e);
		}
		
		super.start();
	}         

	/**
	 * Perform authentication.
	 * 
	 * @param config
	 */
	protected boolean performAuthentication(final Request request, final HttpServletResponse response,
			LoginConfig config) throws IOException {

		// Have we already authenticated someone?
		Principal principal = request.getUserPrincipal();
		String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
		if (principal != null) {
			log.debug("Already authenticated '" + principal.getName() + "'");
			// Associate the session with any existing SSO session
			if (ssoId != null)
				associate(ssoId, request.getSessionInternal(true));
			return (true);
		}

		// check if resubmit after successful authentication
		if (this.matchRequest(request))
			return this.processResubmit(request, response);

		// Request is not authenticated
		final String requestURI = request.getDecodedRequestURI();
		// Is this login action?
		final boolean loginAction = (requestURI.startsWith(request.getContextPath())
				&& requestURI.endsWith(Constants.FORM_ACTION));

		if (!loginAction) {
			// Process regular unauthenticated request. Save request in
			// the session and forward to the configured login page.
			final Session session = request.getSessionInternal(true);
			log.debug("Save request in session '" + session.getIdInternal() + "'");
			try {
				saveRequest(request, session);
			} catch (IOException ioe) {
				log.debug("Error saving request", ioe);
				response.sendError(HttpServletResponse.SC_FORBIDDEN, MESSAGES.requestBodyTooLarge());
				return (false);
			}
			forwardToLoginPage(request, response, config);
			return false;
		}

		// at this point authentication submission (form or OIDC provider response)
		request.getResponse().sendAcknowledgement();

		// get current session and check if expired
		final Session session = request.getSessionInternal(false);
		if (session == null) {
			log.debug("session has expired");

			// redirect to the configured landing page, if any
			if (!this.redirectToLandingPage(request, response))
				response.sendError(HttpServletResponse.SC_REQUEST_TIMEOUT);

			// done, authentication failure
			return false;
		}

		// check if OIDC authentication response or form submission
		for (IDPAuthenticator auth : idpAuthenticators) {
			if (auth.isApplicable(request)) {
				principal = auth.processAuthentication(session, request);
			}
			if (principal != null) {
				break;
			}
		}
		if (principal == null) {
			principal = processLoginFormSubmission(session, request.getParameter(Constants.FORM_USERNAME),
					request.getParameter(Constants.FORM_PASSWORD));
		}

		// check if authentication failure
		if (principal == null) {
			this.forwardToErrorPage(request, response, this.context.getLoginConfig());
			return false;
		}

		// successful authentication
		log.debug("authentication of \"" + principal.getName() + "\" was successful");
		session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);
		String origRequestURI = savedRequestURL(session);
		log.debug("redirecting to original URI: " + origRequestURI);
		request.getResponse().sendRedirect(response.encodeRedirectURL(origRequestURI));
		return false;
	}

	/*
	 * (non-Javadoc) See overridden method.
	 */
	@Override
	protected void forwardToLoginPage(final Request request, final HttpServletResponse response,
			final LoginConfig config) throws IOException {

		// add login configuration request attributes for the page
		for (IDPAuthenticator auth : idpAuthenticators) {
			auth.addRequestAttributes(request);
		}
		if (request.getParameter("source") != null) {
			response.sendRedirect(response.encodeRedirectURL(request.getParameter("source")));
			return;
		}

		// proceed to the login page
		super.forwardToLoginPage(request, response, config);
	}

	/*
	 * (non-Javadoc) See overridden method.
	 */
	@Override
	protected void forwardToErrorPage(final Request request, final HttpServletResponse response,
			final LoginConfig config) throws IOException {

		// add login configuration request attributes for the page
		for (IDPAuthenticator auth : idpAuthenticators) {
			auth.addRequestAttributes(request);
		}
		if (request.getParameter("source") != null) {
			response.sendRedirect(response.encodeRedirectURL(request.getParameter("source")));
			return;
		}

		// proceed to the login error page
		super.forwardToErrorPage(request, response, config);
	}


	/**
	 * Form submission.
	 */
	protected Principal processLoginFormSubmission(final Session session, final String username,
			final String password) {

		log.debug("Authenticating user: [" + username + "] using password");

		final Principal principal = this.context.getRealm().authenticate(username, password);
		if (principal == null) {
			log.debug("Authentication failure realm: " + this.context.getRealm().getInfo());
			return null;
		}

		session.setNote(Constants.SESS_USERNAME_NOTE, username);
		session.setNote(Constants.SESS_PASSWORD_NOTE, password);

		return principal;
	}

	protected boolean redirectToLandingPage(final Request request, final HttpServletResponse response)
			throws IOException {

		if (this.landingPage == null)
			return false;

		final String uri = request.getContextPath() + this.landingPage;

		final SavedRequest savedReq = new SavedRequest();
		savedReq.setMethod("GET");
		savedReq.setRequestURI(uri);
		savedReq.setDecodedRequestURI(uri);
		request.getSessionInternal(true).setNote(Constants.FORM_REQUEST_NOTE, savedReq);

		response.sendRedirect(response.encodeRedirectURL(uri));

		return true;
	}

	protected boolean processResubmit(final Request request, final HttpServletResponse response) throws IOException {

		// get session
		final Session session = request.getSessionInternal(true);

		log.debug("Restore request from session '" + session.getIdInternal() + "'");
		final Principal principal = (Principal) session.getNote(Constants.FORM_PRINCIPAL_NOTE);
		register(request, response, principal, HttpServletRequest.FORM_AUTH,
				(String) session.getNote(Constants.SESS_USERNAME_NOTE),
				(String) session.getNote(Constants.SESS_PASSWORD_NOTE));
		// If we're caching principals we no longer need the username
		// and password in the session, so remove them
		if (cache) {
			session.removeNote(Constants.SESS_USERNAME_NOTE);
			session.removeNote(Constants.SESS_PASSWORD_NOTE);
			for (IDPAuthenticator auth:idpAuthenticators) {
				auth.removeNotes(session);
			}
		}
		if (restoreRequest(request, session)) {
			if (CatalinaLogger.AUTH_LOGGER.isDebugEnabled())
				CatalinaLogger.AUTH_LOGGER.debug("Proceed to restored request");
			return true;
		} else {
			if (CatalinaLogger.AUTH_LOGGER.isDebugEnabled())
				CatalinaLogger.AUTH_LOGGER.debug("Restore of original request failed");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return false;
		}
	}
	
	public String getProviders() {
		return providers;
	}
	
	public void setProviders(String providers) {
		this.providers = providers;
	}
}
