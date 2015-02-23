%--
% Copyright (c) 2012-2015 Yakaz
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

-module(yaws_logger_console).

-behaviour(yaws_extended_logger).


%% yaws_extended_logger callbacks
-export([open_log/5, close_log/1, write/2]).

-record(state, {name       :: atom(),
                type       :: string(),
                servername :: string()}).


%% ===================================================================
%% yaws_extended_logger callbacks.
%% ===================================================================
open_log(Id, ServerName, Type, _Dir, _Opts) ->
    ensure_started(),
    #state{name       = Id,
           servername = ServerName,
           type       = atom_to_list(Type)}.

%% ----
close_log(_State) ->
    ok.

%% ----
write(Msg, State) ->
    io:put_chars(user, [$[, State#state.type, $], $\s, Msg, $\r, $\n]).

%%====================================================================
%% Internal functions
%%====================================================================
ensure_started() ->
    ok.
