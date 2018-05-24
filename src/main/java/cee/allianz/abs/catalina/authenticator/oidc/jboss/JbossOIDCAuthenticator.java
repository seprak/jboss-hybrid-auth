package cee.allianz.abs.catalina.authenticator.oidc.jboss;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;

import cee.allianz.abs.catalina.authenticator.CompositeAuthenticator;

/**
 * <em>OpenID Connect</em> authenticator entry point for 
 * <em>JBoss EAP 6.x</em>.<br/>
 * It extends the FORM authentication functionality.
 *
 * @author vsprk
 */
public class JbossOIDCAuthenticator extends CompositeAuthenticator {

	@Override
	public boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
		return this.performAuthentication(request, response, config);
	}
}
