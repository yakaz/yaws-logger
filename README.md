# yaws-logger: An extended logger for Yaws

**yaws-logger** is an [Erlang/OTP](http://www.erlang.org/) application that
extends logging fonctionnalty of [Yaws](http://yaws.hyber.org). Logs are written
in a customizable format and may be written to the console, to a file, or
through [syloggerl application](https://github.com/yakaz/sysloggerl) or
[lager](https://github.com/basho/lager) applications.


**yaws-logger** is distributed under the terms of the **2-clause BSD license**;
see `COPYING`.


[![Build Status](https://travis-ci.org/yakaz/yaws-logger.svg?branch=master)](https://travis-ci.org/yakaz/yaws-logger)

## Installation

### Rebar

If you use rebar, you can run the following command to build the application:

```bash
rebar compile
```

### Autotools

If you use the Autotools and `make(1)`, run the following commands to build the
application:

```bash
# Generate Autotools files.
autoreconf -vif

# Build the application.
./configure
make

# Install it.
sudo make install
```

The default installation path is your Erlang's distribution libraries directory
(see `code:lib_dir()`).

## Getting started

TODO

## Configuration

TODO

### Predefined log formats

**yaws-logger** defines 3 log formats that can be referenced in the loggers'
configuration by a keyword instead of a format string:

* **common**: [The Common Log Format (CLF)](http://en.wikipedia.org/wiki/Common_Log_Format).
```bash
"%h %l %u %t \"%r\" %s %b"
```

* **combined**: The extended/combined log format. Same as **common** but with
the _Referer_ and the _User-agent_ in addition.
```bash
"%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\""
```

* **default**: Same as **combined** but with the time taken to serve the request
(in microseconds) and the name of the server in addition.
```bash
"%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %D %v"
```

### Custom log formats

Any literal or C-style control character is copied into the log
messages. Literal quotes and backslashes should be escaped with backslashes.

| Format String | Description
| ------------- | -----------
| %%            | The percent sign.
| %a            | The remote IP-address or _0.0.0.0_ if undefined.
| %B            | The size of the response's body.
| %b            | The size of the response's body in CLF format, _i.e._ a '-' rather than a 0 when no bytes are sent.
| %{Foobar}C 	| The contents of cookie `Foobar` in the request sent to the server.
| %D            | The time taken to serve the request, in microseconds.
| %H            | The request protocol, _.e.g._ `HTTP/1.1`.
| %h            | The remote host or _unknown_ if undefined.
| %{Foobar}i    | The contents of `Foobar:` header line in the request sent to the server.
| %l            | The remote logname. This will always return a always '-'.
| %m            | The request method.
| %{Foobar}o    | The contents of `Foobar:` header line in the reply.
| %P            | The erlang process ID that serviced the request.
| %q            | The query string (prepended with a '?' if a query string exists, otherwise an empty string)
| %r            | The First line of request.
| %s            | The Response status code.
| %T            | The time taken to serve the request, in seconds.
| %t            | The time the request was received.
| %U            | The URL path requested without the query string.
| %u            | The remote user
| %v            | The name of the server serving the request.

You can restrict the printing of particular items depending of the HTTP status
code of responses by placing a comma-separated list of status codes immediately
following the '%'. For all codes not matching one in the list, a '-' is printed
instead of the item. The status code list may be preceded by a '!' to indicate
negation.

For example:

```bash
# Logs the User-agent on 400 and 501 errors only.
%400,501{User-agent}i

# Logs the Referer on all requests that do not return one of the three specified codes.
%!200,304,302{Referer}i
```

### Exemples

TODO
