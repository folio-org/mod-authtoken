# mod-authtoken

Copyright (C) 2016-2021 The Open Library Foundation

This software is distributed under the terms of the Apache License,
Version 2.0. See the file "[LICENSE](LICENSE)" for more information.

# Introduction

This module is responsible for filtering all proxy traffic and checking for a
valid token. In addition, it is responsible for retrieving the permissions for
a given user and making decisions regarding access based on user permissions
and defined requirements for a given path. It provides a token creation endpoint
that privileged modules (such as Authentication) may make use of.

# Building

## System requirements

* Java 11

* Apache Maven 3.3.x or higher

## Quick start

    mvn install
    java -jar target/mod-authtoken-far.jar

# Interface

In addition to acting as a filter, the module exposes a few endpoints that are accessible as part as the regular Okapi ecosystem. These endpoints are as follows:

* /token - This endpoint signs and returns an access token (JWT). It requires the permission __auth.signtoken__, which must be defined as a module permission to be used. It accepts a POST of a JSON object, with a field called _payload_ that contains the claims of the token. The token is returned inside of a JSON object (response code 201), containing a field called _token_ that has the token as a value.

* /refreshtoken - This endpoint signs and returns a refresh token (JWE). It requires the permission __auth.signrefreshtoken__, which must be defined as a module permission. It accepts a POST of a JSON object, with required fields of _userId_ and _sub_. The token is returned inside of a JSON object (response code 201), contained in a field called _refreshToken_.

* /refresh - This endpoint takes a valid refresh token and returns a new access token. It accepts a POST of a JSON object, with required field _refreshToken_ that contains the refresh token. It returns a new access token inside of a JSON object (response code 201), contained in a field called _token_.

The expiration time is hard-coded:

* 10 minutes for access tokens
* 24 hours for refresh tokens

[MODAT-65](https://issues.folio.org/browse/MODAT-65) will make it configurable.

# Command Line Options/System Properties

mod-authtoken supports a number of command line options as system properties, set by passing `-D<property.name>=<value>` to the jar when loading.

* `jwt.signing.key` - A passphrase to use as a signing key. Setting this property for all instances of the module allows mod-authtoken to be clustered
* `perm.lookup.timeout` - Timeout for lookups to mod-permissions in seconds. Defaults to 10.
* `user.cache.seconds` - Time to cache user permissions in seconds. Defaults to 60.
* `user.cache.purge.seconds` - Time before a user is purged from the permissions cache in seconds. Defaults to 43200 (12 hours).
* `sys.perm.cache.seconds` - Time that system permissions are cached in seconds. Defaults to 259200 (3 days).
* `sys.perm.cache.purge.seconds` - Time before system permissions are purged from the permissions cache. Defaults to 43200 (12 hours).
* `log.level` - Module log level.
* `port` - Port the module will listen on. Defaults to 8081.
* `cache.permissions` - Boolean controlling the permissions cache. Defaults to `true`.

# Custom Headers

Passing a value of "true" to the Authtoken-Refresh-Cache header for any request will inform mod-authtoken to delete the permissions cache for that userid and to request fresh permissions, regardless of cache age.

# Additional information

[Refresh Tokens Designs and Decisions](https://wiki.folio.org/display/DD/Refresh+Tokens)

Other [modules](https://dev.folio.org/source-code/#server-side).

Other FOLIO Developer documentation is at [dev.folio.org](https://dev.folio.org/)

### Issue tracker

See project [MODAT](https://issues.folio.org/browse/MODAT)
at the [FOLIO issue tracker](https://dev.folio.org/guidelines/issue-tracker/).

### ModuleDescriptor

See the built `target/ModuleDescriptor.json` for the interfaces that this module
requires and provides, the permissions, and the additional module metadata.

### Code analysis

[SonarQube analysis](https://sonarcloud.io/dashboard?id=org.folio%3Amod-authtoken).

### Download and configuration

The built artifacts for this module are available.
See [configuration](https://dev.folio.org/download/artifacts) for repository access,
and the [Docker image](https://hub.docker.com/r/folioorg/mod-authtoken/).
