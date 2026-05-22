# OpenSSL Pascal API 

This is version 2 of the repository and represents a complete update and re-organisation of the
repository. The code generator has been removed from the repository and is now
available in a separate repository (https://github.com/MWASoftware/h2pasng).

This repository provides Pascal Interfaces to the OpenSSL API for the current versions of the
OpenSSL library.

OpenSSL is itself an open source code library providing an implementation that includes 
the RFC 8446 Transport Layer Security (TLS) Protocol Version 1.3. (see https://www.openssl.org/).

The OpenSSL API may be used to support many applications including:

  * secure (https) webserver access
  * secure transport connections
  * X.509 certificate management, and
  * General purpose encryption/decryption for many different ciphers.

The OpenSSL library is written in 'C' and the programmatic interface is defined in a series of 
'C' header files. These have been translated into Pascal units in order to make available the interface 
to a Pascal program. The PascalAPI4OpenSSL package provides a Pascal API to the OpenSSL libraries.

The OpenSSL API is large (Release 4.0.0 contains 145 headers files), making manual translation infeasible. 
This translation is machine driven and is as complete as possible. The main omissions are macros
that cannot be readily translated. These are typically macros that check variable types. Given
that Pascal is already strongly typed, these macros are redundant. Otherwise, some of the more
complex macros are not yet processable by this version of the generator. Note the "stack" macros
are fully translated. .

This API also provides:

    • Different link models
    • Backwards compatibility to earlier versions
    • Delphi and Free Pascal support.

The Header files are provided by OpenSSL version number and the aim is to proper headers for each
currently supported version of OpenSSL starting with the Long Term Support release 3.0.20.

This may be found in the headers/3.0.20 folder, and should be usable with OpenSSL 3.0.x and later. Later 
OpenSSL 3.x headers are also available.

A variant of the 3.0.20 headers may also be found in then headersWithLegacySupport/3.0.20 folder.

This variant includes additional include files that enable support for OpenSSL 1.0.2 and 1.1.1 releases.
(Dynamic Link Model Only). This is not complete support but is limited the functionality needed by
the IndySecOpenSSL package.

See the docs folder for more information.

# Use Cases

The IndySecOpenSSL package (https://github.com/MWASoftware/IndySecOpenSSL) provides example
use cases for the OpenSSL headers supporting secure https communication. 

The main branch of IndySecOpenSSL is equivalent to the previous release and is 
based on the OpenSSL 3.0.20 headers with legacy support for OpenSSL 1.0.2 and 1.1.0. 
Other branches of IndySecOpenSSL are also available each using a different release of the 
OpenSSL headers.

# Licence
The headers are derived from the OpenSSL source code and hence are distributed using the same 
Apache License v2.0 as OpenSSL itself.

Note. The API is large and while the core functionality has been tested using the IndySecOpenSSL 
package,it is not feasible to extensively test all translated headers other than by a “Clean Compile”. 
Users must obtain their own confidence in their use of these headers through their own testing. 
The Pascal OpenSSL headers are distributed in the hope that they may be useful but with no warrantee whatsoever




