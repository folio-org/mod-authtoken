## 2.4.0 2019-12-03

 * MODAT-56 validate user deactivation when checking access token
 * Use new JAVA_OPTIONS MaxRAMPercentage FOLIO-2358
 * Use new base docker image FOLIO-2358

## 2.3.0 2019-09-25

 * MODAT-49 Two caches for permissionsForUser and expandPermissions
 * MODAT-50 Fix Does not pass X-Okapi-Request-Id

## 2.2.1 2019-07-23

* [MODAT-47](https://issues.folio.org/browse/MODAT-47) Incorrect extra permissions handling
* [MODAT-48](https://issues.folio.org/browse/MODAT-48) groovy-eclipse-compiler fail in Eclipse

## 2.2.0 2019-06-11
 * MODAT-43 Bump up token perm cache from 10s to 60s
 * MODAT-44 Fix mod-auth requires permissions interface
 * MODAT-46 checkout-by-barcode returns 500 "HTTP header is larger
   than 8192 bytes

## 2.1.0 2019-03-15
 * No need to include raml-test (not in use)
 * Update to Vertx 3.5.4

## 2.0.4 2019-01-11
 * Fix issue with caching permissions (MODAT-42)

## 2.0.3 2018-12-07
 * Correct version in pom.xml

## 2.0.2 2018-11-30
 * Fix issue with missing module token when acting as filter (MODAT-38, MODAT-39)
 * Enable A256GCM Encryption (MODAT-35, MODAT-36)

## 2.0.1 2018-09-11
 * Code clean-up

## 2.0.0 2018-09-10
 * Implement /refreshtoken and /refresh endpoints for obtaining and using refresh tokens
 * Change return format of /token endpoint to return token in body rather than header

## 1.5.2 2018-09-07
 * Reduce verbosity and level of several logs

## 1.5.1 2018-07-25
 * Merge fix for caching-flush bug

## 1.5.0 2018-07-10
 * Add 'iat' claim to all generated tokens

## 1.4.1 2018-02-27
 * Correct package name in pom

## 1.4.0 2018-02-27
 * Add header to zap cache on demand

## 1.3.0 2018-02-22
 * Implement option for time-based caching
 * Adjust token signing hand-off for new Okapi behavior

## 1.2.0 2017-12-18
 * Change behavior to act as a "headers only" filter in Okapi

## 1.1.0 2017-10-11
 * Allow wildcard permission names in desired permissions

## 1.0.0 2017-09-05
 * Use new id-referenced scheme for retrieving permissions
 * Add userid field to authtoken

## 0.6.1 2016-07-31
 * Fix bug with missing source file

## 0.6.0 2017-7-31
 * Add support for X-Okapi-User-Id header
 * Add support for X-Okapi-Request-Id header

## 0.5.0
 * Expand permission sets provided as modulePermissions to modules
 * Treat 404 for permission lookup as empty permission set
 * Remove keep-alive idle timeout
 * Fix internal dependency

## 0.4.0 2017-10-05

 * Initial release after splitting repository from mod-auth
