package cee.allianz.abs.catalina.authenticator;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;

/**
 * Interface for IDP authenticators
 * 
 * @author vsprk
 *
 */
public interface IDPAuthenticator {

	/**
	 * Perform initialization
	 * 
	 * @throws Exception - if init can't be performed
	 */
	void init(String providers) throws Exception;
	
	/**
	 * Determines if this authenticator is applicable for reqiest type
	 * 
	 * @param request
	 * @return
	 */
	boolean isApplicable(HttpServletRequest request);
	
	/**
	 * Processes authentication with IDP resulting with {@link Principal}
	 * 
	 * @param request
	 * @return the authenticated {@link Principal}
	 */
	Principal processAuthentication(Session session, Request request) throws IOException;
	
	/**
	 * Clear specific notes from catalina session
	 * 
	 * @param session
	 */
	void removeNotes(Session session);

	/**
	 * Adds specific IDP request attributes toi be shown on login or error page.
	 * 
	 * @param request
	 * @throws IOException
	 */
	void addRequestAttributes(Request request)  throws IOException;
}
