%-
% Copyright (c) 2012 Yakaz
% All rights reserved.
%
% Redistribution and use in source and binary forms, with or without
% modification, are permitted provided that the following conditions
% are met:
% 1. Redistributions of source code must retain the above copyright
% notice, this list of conditions and the following disclaimer.
% 2. Redistributions in binary form must reproduce the above copyright
% notice, this list of conditions and the following disclaimer in the
% documentation and/or other materials provided with the distribution.
%
% THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
% ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
% SUCH DAMAGE.

-module(basic_SUITE).

-include("testsuite.hrl").

-export([all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-export([
         load_default_app/1,
         start_stop_default_app/1
        ]).

all() -> [
          load_default_app,
          start_stop_default_app
         ].

%%====================================================================
init_per_suite(Config) ->
    ?INIT_SUITE(Config),
    eunit:start(),
    Config.

end_per_suite(Config) ->
    ?END_SUITE(Config),
    eunit:stop(),
    ok.

%%====================================================================
init_per_testcase(Test, Config) ->
    ?INIT_TESTCASE(Test, Config),
    Config.


end_per_testcase(Test, Config) ->
    ?END_TESTCASE(Test, Config),
    ok.

%%====================================================================
load_default_app(_) ->
    application:load(yaws_logger),

    %% Print default value for mandatory parameters
    yaws_logger_app:show_params(),

    %% Then check their values in accordance with the documentation
    [check_default_param(Param) || Param <- yaws_logger_app:params_list()],

    ok.

check_default_param(default_accesslog_format) ->
    ?assertEqual(default, yaws_logger_app:get_param(default_accesslog_format));
check_default_param(revproxy_whitelist) ->
    ?assertEqual([], yaws_logger_app:get_param(revproxy_whitelist));
check_default_param(handlers) ->
    ?assertEqual([], yaws_logger_app:get_param(handlers)).



%% ----
start_stop_default_app(_) ->
    ?assertEqual(ok, application:start(yaws_logger)),
    ?assertEqual(ok, application:stop(yaws_logger)),
    ok.

