# mod-authtoken

Copyright (C) 2016-2023 The Open Library Foundation

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

In addition to acting as a filter, the module exposes a few endpoints that are accessible as part as the regular Okapi ecosystem. This module uses OpenAPI to define its endpoints. Please see the token-1.0.yaml for the documentation of its endpoints.

# Command Line Options/System Properties

mod-authtoken supports a number of command line options as system properties, set by passing `-D<property.name>=<value>` to the jar when loading.

* `jwt.signing.key` - A passphrase to use as a signing key. If not set a random key is generated on each module restart invalidating all previously issued tokens. For clustering all instances of mod-authtoken must be configured to use the same key.
* `perm.lookup.timeout` - Timeout for lookups to mod-permissions in seconds. Defaults to 10.
* `user.cache.seconds` - Time to cache user permissions in seconds. Defaults to 60.
* `user.cache.purge.seconds` - Time before a user is purged from the permissions cache in seconds. Defaults to 43200 (12 hours).
* `sys.perm.cache.seconds` - Time that system permissions are cached in seconds. Defaults to 259200 (3 days).
* `sys.perm.cache.purge.seconds` - Time before system permissions are purged from the permissions cache. Defaults to 43200 (12 hours).
* `log.level` - Module log level.
* `port` - Port the module will listen on. Defaults to 8081.
* `cache.permissions` - Boolean controlling the permissions cache. Defaults to `true`.
* `allow.cross.tenant.requests` - Boolean to allow (in consortia setups) or deny cross tenant requests. Defaults to `false`.

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

See the [ModuleDescriptor](descriptors/ModuleDescriptor-template.json)
for the interfaces that this module requires and provides, the permissions,
and the additional module metadata.

### API descriptions:

 * [OpenAPI](src/main/resources/openapi/)
 * [Schemas](src/main/resources/openapi/schemas/)

Generated [API documentation](https://dev.folio.org/reference/api/#mod-authtoken).


### Code analysis

[SonarQube analysis](https://sonarcloud.io/dashboard?id=org.folio%3Amod-authtoken).

### Download and configuration

The built artifacts for this module are available.
See [configuration](https://dev.folio.org/download/artifacts) for repository access,
and the [Docker image](https://hub.docker.com/r/folioorg/mod-authtoken/).
