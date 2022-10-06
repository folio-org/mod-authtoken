## 2.11.1 2022-10-06

 * [MODAT-136](https://issues.folio.org/browse/MODAT-136) Fix Upgrade from 2.9.1 (Lotus) to 2.11.0 (Morning Glory) fails
 * [MODAT-137](https://issues.folio.org/browse/MODAT-137) Upgrade to Vert.x 4.3.3 fixing https for WebClient

## 2.11.0 2022-06-16

This is the first version of mod-authtoken that uses Postgresql storage.

 * [MODAT-132](https://issues.folio.org/browse/MODAT-132) Upgrade dependencies (folio-vertx-lib 2.0.0, Vert.x 4.3.1, ..
 * [MODAT-128](https://issues.folio.org/browse/MODAT-128) jwt.signing.key hint on BadSignatureException
 * [MODAT-126](https://issues.folio.org/browse/MODAT-126) Implement OpenAPI
 * [MODAT-123](https://issues.folio.org/browse/MODAT-123) Report "no token" when permission required and token missing
 * [MODAT-125](https://issues.folio.org/browse/MODAT-125) Update dependencies (CVE-2021-27568, CVE-2021-31684)
 * [MODAT-112](https://issues.folio.org/browse/MODAT-112) Implement access token expiration and refresh token rotation
 * [MODAT-110](https://issues.folio.org/browse/MODAT-110) Implement token persistent store

## 2.10.0 2022-02-18

Fixes:

 * [MODAT-122](https://issues.folio.org/browse/MODAT-122) Vert.x 4.2.4, Log4j 2.17.1
 * [MODAT-108](https://issues.folio.org/browse/MODAT-108) Bad error message: out of bounds exception

Improvements:

 * [MODAT-120](https://issues.folio.org/browse/MODAT-120) Define permissions auth.signtoken, auth.signrefreshtoken
 * [MODAT-118](https://issues.folio.org/browse/MODAT-118) Clear permission cache when user logs in
 * [MODAT-117](https://issues.folio.org/browse/MODAT-117) Redundant web service request
 * [MODAT-109](https://issues.folio.org/browse/MODAT-109) Implement new token types

## 2.9.1 2021-12-14

 * [MODAT-115](https://issues.folio.org/browse/MODAT-115) Log4j 2.16.0, disable JNDI
 * [MODAT-113](https://issues.folio.org/browse/MODAT-113) Log4j 2.15.0 fixing remote execution
 * [MODAT-108](https://issues.folio.org/browse/MODAT-108) Out of bounds exception
 * [MODAT-107](https://issues.folio.org/browse/MODAT-107) X-Okapi-MOdule-Tokens, refactor

## 2.9.0 2021-09-29

 * Support /admin/health
Other:
 * Upgrade to Vert.x 4.1.4, okapi-common 4.9.0
 * Notes on refresh tokens.

## 2.8.0 2021-05-27

No functional changes since 2.7.0.

 * Upgrade to Vert.x 4.1.0.CR1
 * [MODAT-92](https://issues.folio.org/browse/MODAT-92) Add personal data disclosure form
 * Support both "http.port" and "port" property variables

## 2.7.0 2021-03-01

Update mod-authtoken to use same log format as RMB and Okapi. Upgrade from
Vert.x 3 to 4. Token cache optimization and bug fix.

 * [MODAT-98](https://issues.folio.org/browse/MODAT-98) log4j2 format, Vert.x 4.0.2
 * [MODAT-82](https://issues.folio.org/browse/MODAT-82) Replace linear search MainVerticle.LimitedSizeQueue
 * [MODAT-96](https://issues.folio.org/browse/MODAT-96) Upgrade mod-authtoken to Vert.x 4.0.0
 * [MODAT-63](https://issues.folio.org/browse/MODAT-63) Update log4j from 1.x API to 2 API

## 2.6.0 2020-09-30

 * [MODAT-89](https://issues.folio.org/browse/MODAT-89) Upgrade to Vertx 3.9.3
 * [MODAT-88](https://issues.folio.org/browse/MODAT-88) Migrate to JDK 11
 * [MODAT-86](https://issues.folio.org/browse/MODAT-86) Remove requestId from token claims

## 2.5.1 2020-06-25

 * [MODAT-79](https://issues.folio.org/browse/MODAT-79) Fix Error: 414 Request-URI Too Large. Fixed by skipping
   expanded system permissions
 * [MODAT-78](https://issues.folio.org/browse/MODAT-78) refresh system perm set expansion if it is empty

## 2.5.0 2020-06-04

 * [MODAT-77](https://issues.folio.org/browse/MODAT-77) Provide permissionsRequired property.
 * [MODAT-76](https://issues.folio.org/browse/MODAT-76) Update to Vert.x 3.9.1
 * [MODAT-72](https://issues.folio.org/browse/MODAT-72) Expand module permission set
 * [MODAT-61](https://issues.folio.org/browse/MODAT-61) Increase HTTP client pool size.
 * [MODAT-62](https://issues.folio.org/browse/MODAT-62) Issue with log4j configuration.
 * [MODAT-59](https://issues.folio.org/browse/MODAT-59) Update log4j from 1.2.17 to 2.x fixing security vulnerability CVE-2019-17571

## 2.4.0 2019-12-03

 * [MODAT-56](https://issues.folio.org/browse/MODAT-56) validate user deactivation when checking access token
 * Use new JAVA_OPTIONS MaxRAMPercentage FOLIO-2358
 * Use new base docker image FOLIO-2358

## 2.3.0 2019-09-25

 * [MODAT-49](https://issues.folio.org/browse/MODAT-49) Two caches for permissionsForUser and expandPermissions
 * [MODAT-50](https://issues.folio.org/browse/MODAT-50) Fix Does not pass X-Okapi-Request-Id

## 2.2.1 2019-07-23

* [MODAT-47](https://issues.folio.org/browse/MODAT-47) Incorrect extra permissions handling
* [MODAT-48](https://issues.folio.org/browse/MODAT-48) groovy-eclipse-compiler fail in Eclipse

## 2.2.0 2019-06-11
 * [MODAT-43](https://issues.folio.org/browse/MODAT-43) Bump up token perm cache from 10s to 60s
 * [MODAT-44](https://issues.folio.org/browse/MODAT-44) Fix mod-auth requires permissions interface
 * [MODAT-46](https://issues.folio.org/browse/MODAT-46) checkout-by-barcode returns 500 "HTTP header is larger
   than 8192 bytes

## 2.1.0 2019-03-15
 * No need to include raml-test (not in use)
 * Update to Vertx 3.5.4

## 2.0.4 2019-01-11
 * Fix issue with caching permissions ([MODAT-42](https://issues.folio.org/browse/MODAT-42))

## 2.0.3 2018-12-07
 * Correct version in pom.xml

## 2.0.2 2018-11-30
 * Fix issue with missing module token when acting as filter
   ([MODAT-38](https://issues.folio.org/browse/MODAT-38), [MODAT-39](https://issues.folio.org/browse/MODAT-39))
 * Enable A256GCM Encryption ([MODAT-35](https://issues.folio.org/browse/MODAT-35), [MODAT-36](https://issues.folio.org/browse/MODAT-36))

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
