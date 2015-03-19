%--
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

-module(yaws_logger_sysloggerl).

-behaviour(yaws_extended_logger).


%% yaws_extended_logger callbacks
-export([open_log/5, close_log/1, write/2]).

-record(state, {name     :: atom(),
                ident    :: string(),
                priority :: syslog:priority(),
                options  :: list()}).


%% ===================================================================
%% yaws_extended_logger callbacks.
%% ===================================================================
open_log(Id, ServerName, Type, _Dir, Opts) ->
    ensure_started(),

    Name       = {?MODULE, Id},
    Ident      = syslog_ident(ServerName, Type, Opts),
    Facility   = syslog_facility(ServerName, Type, Opts),
    Level      = syslog_loglevel(ServerName, Type, Opts),
    SyslogOpts = syslog_options(ServerName, Type, Opts),
    Priority   = syslog:priority(Facility, Level),

    case syslog:logger(Name) of
        not_found -> syslog:set(Name, Ident, Priority, SyslogOpts);
        _Logger   -> ok
    end,

    #state{name     = Name,
           ident    = Ident,
           priority = Priority,
           options  = SyslogOpts}.

%% ----
close_log(State) ->
    syslog:unset(State#state.name).

%% ----
write(Msg, State) ->
    syslog:log(State#state.name, State#state.priority, Msg, []).

%%====================================================================
%% Internal functions
%%====================================================================
ensure_started() ->
    Apps = application:which_applications(),
    case lists:keymember(sysloggerl, 1, Apps) of
        true ->
            ok;
        false ->
            case application:start(sysloggerl) of
                ok                            -> ok;
                {error, {already_started, _}} -> ok;
                Else                          -> throw(Else)
            end
    end.

%% ----
syslog_ident(ServerName, _Type, Opts) ->
    case lists:keyfind(syslog_ident, 1, Opts) of
        {syslog_ident, Ident} -> Ident;
        false                 -> ServerName
    end.

%% ---
syslog_facility(_ServerName, _Type, Opts) ->
    case lists:keyfind(syslog_facility, 1, Opts) of
        {syslog_facility, Facility} -> Facility;
        false                       -> daemon
    end.

%% ---
syslog_loglevel(_ServerName, _Type, Opts) ->
    case lists:keyfind(syslog_loglevel, 1, Opts) of
        {syslog_loglevel, Level} -> Level;
        false                    -> info
    end.

%% ----
syslog_options(_ServerName, _Type, Opts) ->
    case lists:keyfind(syslog_options, 1, Opts) of
        {syslog_options, Options} -> Options;
        false                     -> []
    end.
