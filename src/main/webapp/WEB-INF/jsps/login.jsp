<%@page pageEncoding="UTF-8" trimDirectiveWhitespaces="true" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<c:set var="authEndpoints" value="${requestScope['cee.allianz.abs.oidc.authEndpoints']}"/>
<!DOCTYPE html>
<html lang="en">
 
  <head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css">
  </head>
  
  <body class="container py-4">
    <div class="row">
      <div class="col">
        <h1>Login</h1>
        <p>The login page allows the user to choose preferred way to login.</p>
      </div>
    </div>
    <div class="row">
      <div class="col">
        <h2>Using OpenID Connect</h2>
        <p>The list of configured providers. Choose one and proceed to the OP login page</p>
        <ul>
          <c:forEach items="${authEndpoints}" var="ep">
            <li><a href="${ep.url}"><c:out value="${ep.name}"/></a></li>
          </c:forEach>
        </ul>
      </div>
    </div>
    
    <c:set var="error" value="${requestScope['cee.allianz.abs.oidc.error']}"/>
    <c:if test="${!empty error}">
	    <div class="row">
	      <div class="col">
	        <h2>Provider Error Response</h2>
	        <ul>
	          <li>Error Code: <c:out value="${error.code}"/></li>
	          <c:if test="${!empty error.description}">
	          <li>Error Description: <c:out value="${error.description}"/></li>
	          </c:if>
	          <c:if test="${!empty error.infoPageURI}">
	            <li>More info at <a href="${error.infoPageURI}"><c:out value="${error.infoPageURI}"/></a></li>
	          </c:if>
	        </ul>
	      </div>
	    </div>
    </c:if>
  </body>
</html>
