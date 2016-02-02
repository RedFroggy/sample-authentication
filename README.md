THREE PASS AUTHENTICATION
==========

# Presentation
This prototype is used to demonstrate the three pass authentication process.

A client, and a server will mutually authentified and all sent messages by client will be crypted.
An AES 128bits key is used. By default, the port 12345 is used.

# Run
Server : mvn exec:java -Pserver
Client : mvn exec:java -Pclient

# CI
Develop: [![Build Status](https://api.travis-ci.org/RedFroggy/sample-authentication.svg?branch=develop)](https://travis-ci.org/RedFroggy/sample-authentication)
Master: [![Build Status](https://api.travis-ci.org/RedFroggy/sample-authentication.svg?branch=master)](https://travis-ci.org/RedFroggy/sample-authentication)