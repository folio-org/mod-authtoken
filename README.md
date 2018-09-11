# mod-authtoken

Copyright (C) 2016-2018 The Open Library Foundation

This software is distributed under the terms of the Apache License,
Version 2.0. See the file "[LICENSE](LICENSE)" for more information.

# Introduction

This module is responsible for filtering all proxy traffic and checking for a
valid token. In addition, it is responsible for retrieving the permissions for
a given user and making decisions regarding access based on user permissions
and defined requirements for a given path. It provides a token creation endpoint
that privileged modules (such as Authentication) may make use of.

# Interface

In addition to acting as a filter, the module exposes a few endpoints that are accessible as part as the regular Okapi ecosystem. These endpoints are as follows:

* /token - This endpoint signs and returns an access token (JWT). It requires the permission __auth.signtoken__, which must be defined as a module permission to be used. It accepts a POST of a JSON object, with a field called _payload_ that contains the claims of the token. The token is returned inside of a JSON object (response code 201), containing a field called _token_ that has the token as a value.

* /refreshtoken - This endpoint signs and returns a refresh token (JWE). It requires the permission __auth.signrefreshtoken__, which must be defined as a module permission. It accepts a POST of a JSON object, with required fields of _userId_ and _sub_. The token is returned inside of a JSON object (response code 201), contained in a field called _refreshToken_. 

* /refresh - This endpoint takes a valid refresh token and returns a new access token. It accepts a POST of a JSON object, with required field _refreshToken_ that contains the refresh token. It returns a new access token inside of a JSON object (response code 201), contained in a field called _token_.

# Additional information

The [raml-module-builder](https://github.com/folio-org/raml-module-builder) framework.

See project [MODAT](https://issues.folio.org/browse/MODAT)
at the [FOLIO issue tracker](https://dev.folio.org/guidelines/issue-tracker/).

Other [modules](https://dev.folio.org/source-code/#server-side).

Other FOLIO Developer documentation is at [dev.folio.org](https://dev.folio.org/)

# Command Line Options

mod-authtoken employs a caching mechanism to avoid repeated lookups to the permissions module for rapid incoming requests. This is enabled by default, though it may be disabled by passing -Dcache.permissions=false to the jar when loading.

# Custom Headers

Passing a value of "true" to the Authtoken-Refresh-Cache header for any request will inform mod-authtoken to delete the permissions cache for that userid and to request fresh permissions, regardless of cache age.
