# mod-authtoken

Copyright (C) 2017 The Open Library Foundation

This software is distributed under the terms of the Apache License,
Version 2.0. See the file "[LICENSE](LICENSE)" for more information.

# Introduction

This module is responsible for filtering all proxy traffic and checking for a
valid token. In addition, it is responsible for retrieving the permissions for
a given user and making decisions regarding access based on user permissions
and defined requirements for a given path. It provides a token creation endpoint
that privileged modules (such as Authentication) may make use of.

# Additional information

The [raml-module-builder](https://github.com/folio-org/raml-module-builder) framework.

Other [modules](http://dev.folio.org/source-code/#server-side).

Other FOLIO Developer documentation is at [dev.folio.org](http://dev.folio.org/)
