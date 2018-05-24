<%@page pageEncoding="UTF-8" trimDirectiveWhitespaces="true" %>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Home</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css">
  </head>
  <body class="container py-4">
    <div class="row">
      <div class="col">
        <h1>Home</h1>
        <p>This page is default public home page</p>
      </div>
    </div>
    <div class="row">
      <div class="col">
        <h2>Secure Pages</h2>
        <p>Navigating to any of these pages should trigger user login if no user is currently authenticated for the session.</p>
        <ul>
          <li><a href="secure/page-RAP">RAP</a></li>
          <li><a href="secure/page-CISL">CISL</a></li>
        </ul>
      </div>
    </div>
  </body>
</html>
