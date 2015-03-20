# yaws-logger: An extended logger for Yaws

**yaws-logger** is an [Erlang/OTP](http://www.erlang.org/) application that
extends logging fonctionnalty of [Yaws](http://yaws.hyber.org). Logs are written
in a customizable format and may be written to the console, to a file, or
through [syloggerl](https://github.com/yakaz/sysloggerl) or
[lager](https://github.com/basho/lager) applications.


**yaws-logger** is distributed under the terms of the **2-clause BSD license**;
see `COPYING`.


[![Build Status](https://travis-ci.org/yakaz/yaws-logger.svg?branch=master)](https://travis-ci.org/yakaz/yaws-logger)

Table of contents
-----------------
 - [Installation](#installation)
  - [Rebar](#rebar)
  - [Autotools](#autotools)
 - [How it works!](#how-it-works)
 - [Configuration](#configuration)
  - [Handlers definition](#handlers-definition)
  - [Predefined log formats](#predefined-log-formats)
  - [Custom log formats](#custom-log-formats)
  - [Examples](#examples)

## Installation

### Rebar

If you use rebar, you can run the following command to build the application:

```bash
rebar compile
```

The testsuite is implemented using the
[Common Test framework](http://www.erlang.org/doc/apps/common_test/users_guide.html). To
run it with rebar:

```bash
rebar ct
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

# Run the testsuite
make check USE_COVER=yes

# Install it.
sudo make install
```

The default installation path is your Erlang's distribution libraries directory
(see [`code:lib_dir()`](http://www.erlang.org/doc/man/code.html#lib_dir-0)).

## How it works!

TODO

## Configuration

You can configure **yaws-logger** application by setting parametters in the
application environment:

* `{default_accesslog_format, default | common | combined | string()}`

Defines the default format used for access logs. All handlers will inherite this
format but they can overwrite it when necessary. Default value: `default`.  
See [Predefined log formats](#predefined-log-formats) and
[Custom log formats](#custom-log-formats) for details about supported formats.

* `{revproxy_whitelist, [string()]}`

Defines the list of whitelisted IP addresses (or address blocks) that will be
considered as trusted reverse proxies. It will be used to retrieve the *real*
client IP address by extracting it from the
[`X-Forwarded-For`](http://en.wikipedia.org/wiki/X-Forwarded-For) header.
Default value: `[]`.

* `{handlers, [handler()]}`

Defines access/auth log handlers. Each handler is represented by a unique
identifier. See [Handlers definition](#handlers-definition) for details about
the handlers. Default value: `[]`.

### Handlers definition

```erlang
handler()     :: {Id, Opts}
  Id          :: atom()
  Opts        :: [{backend, backend()}, {type, logger_type()}, {vhost, Regex} | BackendOpts]
  Regex       :: iolist()
  BackendOpts :: [BackendOpt]
  BackendOpt  :: console_option() | file_option() | sysloggerl_option() | lager_option()


backend()     :: yaws_logger_console | yaws_logger_file | yaws_logger_sysloggerl | yaws_logger_lager
logger_type() :: any | auth | access


common_option()  :: {accesslog_format, default | common | combined | string()}

console_option() :: common_option()

file_option()    :: common_option()
                  | {file,   file:filename()}
                  | {size,   pos_integer() | infinity}
                  | {rotate, non_neg_integer()}
                  | {sync,   boolean()}

sysloggerl_option() :: common_option()
                     | {syslog_ident,    string()}
                     | {syslog_facility, syslog:facility()}
                     | {syslog_loglevel, syslog:loglevel()}

lager_option() :: common_option()
                | {lager_loglevel, lager:log_leve()}
```

### Predefined log formats

**yaws-logger** defines 3 log formats that can be referenced in the handlers
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
| _%%_          | The percent sign.
| _%a_          | The remote IP address or _0.0.0.0_ if undefined.
| _%{real}a_    | The *real* client IP address or _0.0.0.0_ if undefined.
| _%B_          | The size of the response's body.
| _%b_          | The size of the response's body in CLF format, _i.e._ a '-' rather than a 0 when no bytes are sent.
| _%{Foobar}C_ 	| The contents of cookie `Foobar` in the request sent to the server.
| _%D_          | The time taken to serve the request, in microseconds.
| _%H_          | The request protocol, _.e.g._ `HTTP/1.1`.
| _%h_          | The remote host or _unknown_ if undefined.
| _%{real}h_    | The *real* client host or _unknown_ if undefined.
| _%{Foobar}i_  | The contents of `Foobar:` header line in the request sent to the server.
| _%l_          | The remote logname. This will always return a always '-'.
| _%m_          | The request method.
| _%{Foobar}o_  | The contents of `Foobar:` header line in the reply.
| _%P_          | The erlang process ID that serviced the request.
| _%q_          | The query string (prepended with a '?' if a query string exists, otherwise an empty string)
| _%r_          | The First line of request.
| _%s_          | The Response status code.
| _%T_          | The time taken to serve the request, in seconds.
| _%t_          | The time the request was received.
| _%U_          | The URL path requested without the query string.
| _%u_          | The remote user
| _%v_          | The name of the server serving the request.

You can restrict the printing of particular items depending of the HTTP status
code of responses by placing a comma-separated list of status codes immediately
following the '%'. For all codes not matching one in the list, a '-' is printed
instead of the item. The status code list may be preceded by a '!' to indicate
negation.

For example:

```bash
# Logs the User-agent on 400 and 501 errors only. For other status codes, the literal string "-" will be logged
%400,501{User-agent}i

# Logs the Referer on all requests that do not return one of the three specified codes, "-" otherwise.
%!200,304,302{Referer}i
```

### Examples

TODO
