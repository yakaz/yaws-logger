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

### Exemples

TODO
