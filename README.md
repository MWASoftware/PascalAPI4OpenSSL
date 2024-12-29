# OpenSSL Pascal API Code Generator

This program is a Code Generator for creating a Pascal Interface to the OpenSSL API. 
OpenSSL is itself an open source code library providing an implementation that includes 
the RFC 8446 Transport Layer Security (TLS) Protocol Version 1.3. (see https://www.openssl.org/).

The OpenSSL library is written in 'C' and the programmatic interface is defined in a series of 
'C' header files. These have to be translated into Pascal units in order to declare the interface 
to a Pascal code library.

Utilities, such as Free Pascal's h2pas can help this process - but only to the extent of 
creating a set of Pascal constant and type definitions and Function/Procedure 
declarations - and even then there is usually the need for additional file edits 
to cope with some of the more difficult translations, especially where 'C' macros are 
concerned, and to convert the output function/procedure declarations into external declarations.

This code generator takes (template) header files created from OpenSSL '.h' files using a 
utility such as h2pas, and generating a set of Pascal units that supports the 
latest OpenSSL API that provides for:

    • Different link models
    • Backwards compatibility to earlier versions
    • Delphi and Free Pascal support.

For more information on the Code Generator, how it works, how to compile and use it and to
use the generated header files see the provided documentation in the /docs folder.
