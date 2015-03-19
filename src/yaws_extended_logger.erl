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

-module(yaws_extended_logger).

-behaviour(yaws_logger).

-include("yaws_logger.hrl").

-export([behaviour_info/1]).

%% yaws_logger callbacks
-export([open_log/3, close_log/3, wrap_log/4, write_log/4]).

-record(logger, {id                 :: atom(),
                 type               :: any | access | auth,
                 backend            :: atom(),
                 options            :: list(),
                 state              :: any(),
                 accesslog_format   :: [tuple()],
                 revproxy_whitelist :: list()}).

-record(state, {loggers :: [#logger{}]}).

%% ===================================================================
%% yaws_logger callbacks.
%% ===================================================================
behaviour_info(callbacks) ->
    [{open_log,5}, {close_log,1}, {write,2}];
behaviour_info(_Other) ->
    undefined.


%% ===================================================================
%% yaws_logger callbacks.
%% ===================================================================
open_log(ServerName, Type, Dir) ->
    try
        ensure_started(),
        Loggers = get_loggers(ServerName, Type, Dir),
        case Loggers of
            [] ->
                ?WARN("No logger found for to log ~p messages for server ~p~n",
                      [Type, ServerName]);
            _ ->
                ok
        end,
        {true, #state{loggers=Loggers}}
    catch
        _:Error ->
            ?ERROR("Failed to start yaws_logger for the vhost ~p: ~p~n"
                   "== Stack trace ==~n    ~p",
                   [ServerName, Error, erlang:get_stacktrace()]),
            false
    end.
%% ----
close_log(_ServerName, _Type, State) ->
    [(L#logger.backend):close_log(L#logger.state) || L <- State#state.loggers].

%% ----
wrap_log(_ServerName, _Type, State, _Sz) ->
    State.

%% ----
write_log(ServerName, access, State, Data) ->
    [if
         L#logger.type == any; L#logger.type == access ->
             Msg = yaws_logger_formatter:accesslog(L#logger.accesslog_format,
                                                   ServerName,
                                                   L#logger.revproxy_whitelist,
                                                   Data),
             (L#logger.backend):write(Msg, L#logger.state);
         true ->
             ok
     end  || L <- State#state.loggers];
write_log(ServerName, auth, State, Data) ->
    [if
         L#logger.type == any; L#logger.type == auth ->
             Msg = yaws_logger_formatter:authlog(ServerName, Data),
             (L#logger.backend):write(Msg, L#logger.state);
         true ->
             ok
     end  || L <- State#state.loggers];
write_log(_, _, _, _) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
ensure_started() ->
    Apps = application:which_applications(),
    case lists:keymember(yaws_logger, 1, Apps) of
        true ->
            ok;
        false ->
            case application:start(yaws_logger) of
                ok                            -> ok;
                {error, {already_started, _}} -> ok;
                Else                          -> throw(Else)
            end
    end.


%% ----
get_loggers(ServerName, Type, Dir) ->
    Loggers = yaws_logger_app:get_param(loggers),
    filter_loggers(ServerName, Type, Dir, Loggers).

filter_loggers(_, _, _, []) ->
    [];
filter_loggers(ServerName, Type, Dir, [{Id,Config}|Rest]) ->
    RE         = get_vhost(Config),
    LoggerType = get_type(Config),

    case re:run(ServerName, RE, [{capture, none}, caseless, unicode]) of
        match when LoggerType == Type; LoggerType == any ->
            Backend     = get_backend(Config),
            Options     = get_backend_options(Config),
            AccssLogFmt = get_accesslog_format(Config),
            RevProxies  = get_revproxy_whitelist(Config),
            State       = Backend:open_log(Id, ServerName, Type, Dir, Options),

            Logger = #logger{id                 = Id,
                             type               = LoggerType,
                             backend            = Backend,
                             state              = State,
                             options            = Options,
                             accesslog_format   = AccssLogFmt,
                             revproxy_whitelist = RevProxies},

            [Logger|filter_loggers(ServerName, Type, Dir, Rest)];
        _ ->
            filter_loggers(ServerName, Type, Dir, Rest)
    end.

get_vhost(Config) ->
    proplists:get_value(vhost, Config, "").

get_type(Config) ->
    proplists:get_value(type,  Config, any).

get_backend(Config) ->
    proplists:get_value(backend, Config).

get_backend_options([]) ->
    [];
get_backend_options([{vhost, _}|Rest]) ->
    get_backend_options(Rest);
get_backend_options([{type, _}|Rest]) ->
    get_backend_options(Rest);
get_backend_options([{backend, _}|Rest]) ->
    get_backend_options(Rest);
get_backend_options([{access_logformat, _}|Rest]) ->
    get_backend_options(Rest);
get_backend_options([{revproxy_whitelist, _}|Rest]) ->
    get_backend_options(Rest);
get_backend_options([Opt|Rest]) ->
    [Opt|get_backend_options(Rest)].

get_accesslog_format(Config) ->
    Fmt = case lists:keyfind(accesslog_format, 1, Config) of
              {accesslog_format, F} -> F;
              false -> yaws_logger_app:get_param(default_accesslog_format)
          end,
    yaws_logger_formatter:parse_accesslog_format(Fmt).

get_revproxy_whitelist(_Config) ->
    Ls = yaws_logger_app:get_param(revproxy_whitelist),
    yaws_logger_formatter:parse_revproxy_whitelist(Ls).
