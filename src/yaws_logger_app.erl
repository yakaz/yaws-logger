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

-module(yaws_logger_app).

-behaviour(application).

-include("yaws_logger.hrl").

%% Configuration API.
-export([
         params_list/0,
         get_param/1,
         is_param_valid/2,
         set_param/2,
         check_and_set_param/2,
         show_params/0,
         check_params/0,
         log_param_errors/1
        ]).

%% API
-export([
         backends/0,
         types/0
        ]).

%% application(3erl) callbacks.
-export([
         start/2,
         prep_stop/1,
         stop/1,
         config_change/3
        ]).

%% ===================================================================
%% Configuration API.
%% ===================================================================
-spec params_list() -> [atom()].

params_list() ->
    [
     default_accesslog_format,
     revproxy_whitelist,
     handlers
    ].

%% ----
-spec get_param(atom()) -> any().

get_param(Param) ->
    {ok, Value} = application:get_env(?APPLICATION, Param),
    Value.

%% ----
-spec is_param_valid(atom(), any()) -> boolean().

is_param_valid(default_accesslog_format, Fmt) ->
    (Fmt == default  orelse
     Fmt == common   orelse
     Fmt == combined orelse
     is_list(Fmt));
is_param_valid(revproxy_whitelist, L) ->
    lists:all(fun(Str) -> io_lib:printable_list(Str) end, L);
is_param_valid(handlers, L) when is_list(L) ->
    case (length(L) == sets:size(sets:from_list(L))) of
        true ->
            lists:all(fun({Id,C}) ->
                              (is_atom(Id) andalso is_handler_valid(Id,C))
                      end, L);
        false ->
            ?ERROR("duplicate entry found in the handler list~n"),
            false
    end;
is_param_valid(_, _) ->
    false.

is_handler_valid(Id, Config) ->
    case lists:keyfind(backend, 1, Config) of
        {backend, B} ->
            case lists:member(B, backends()) of
                true ->
                    is_handler_valid(Id, B, Config);
                false ->
                    ?ERROR("Handler '~p': unsupported backend ~p~n", [Id, B]),
                    false
            end;
        false ->
            ?ERROR("Handler '~p': No backend found~n", [Id]),
            false
    end.

%% Check generic handler options
is_handler_valid(_, _, []) ->
    true;
is_handler_valid(Id, Backend, [{backend, Backend}|Rest]) ->
    is_handler_valid(Id, Backend, Rest);
is_handler_valid(Id, Backend, [{vhost, H}|Rest]) ->
    case is_list(H) of
        true ->
            is_handler_valid(Id, Backend, Rest);
        false ->
            ?ERROR("Handler '~p': invalid vhost ~p~n", [Id, H]),
            false
    end;
is_handler_valid(Id, Backend, [{type, Type}|Rest]) ->
    case lists:member(Type, types()) of
        true ->
            is_handler_valid(Id, Backend, Rest);
        false ->
            ?ERROR("Handler '~p': unsupported log type ~p~n", [Id, Type]),
            false
    end;
is_handler_valid(Id, Backend, [{accesslog_format, Fmt}|Rest]) ->
    case (Fmt == default  orelse
          Fmt == common   orelse
          Fmt == combined orelse
          is_list(Fmt)) of
        true ->
            is_handler_valid(Id, Backend, Rest);
        false ->
            ?ERROR("Handler '~p': bad access format ~p~n", [Id, Fmt]),
            false
    end;

%% Check file handler options
is_handler_valid(Id, yaws_logger_file, [{file, F}|Rest]) ->
    case is_list(F) of
        true ->
            is_handler_valid(Id, yaws_logger_file, Rest);
        false ->
            ?ERROR("Handler '~p': invalid file ~p~n", [Id, F]),
            false
    end;
is_handler_valid(Id, yaws_logger_file, [{size, Sz}|Rest]) ->
    case ((is_integer(Sz) andalso Sz > 0) orelse Sz == infinity) of
        true ->
            is_handler_valid(Id, yaws_logger_file, Rest);
        false ->
            ?ERROR("Handler '~p': invalid file size ~p~n", [Id, Sz]),
            false
    end;
is_handler_valid(Id, yaws_logger_file, [{rotate, N}|Rest]) ->
    case (is_integer(N) andalso N >= 0) of
        true ->
            is_handler_valid(Id, yaws_logger_file, Rest);
        false ->
            ?ERROR("Handler '~p': invalid rotate value ~p~n", [Id, N]),
            false
    end;
is_handler_valid(Id, yaws_logger_file, [{sync, B}|Rest]) ->
    case is_boolean(B) of
        true ->
            is_handler_valid(Id, yaws_logger_file, Rest);
        false ->
            ?ERROR("Handler '~p': invalid sync flag ~p~n", [Id, B]),
            false
    end;

%% Check sysloggerl handler options
is_handler_valid(Id, yaws_logger_sysloggerl, [{syslog_ident, Ident}|Rest]) ->
    case io_lib:printable_list(Ident) of
        true ->
            is_handler_valid(Id, yaws_logger_sysloggerl, Rest);
        false ->
            ?ERROR("Handler '~p': invalid syslog ident ~p~n", [Id, Ident]),
            false
    end;
is_handler_valid(Id, yaws_logger_sysloggerl, [{syslog_facility, F}|Rest]) ->
    case syslog:is_facility_valid(F) of
        true ->
            is_handler_valid(Id, yaws_logger_sysloggerl, Rest);
        false ->
            ?ERROR("Handler '~p': invalid syslog facility ~p~n", [Id, F]),
            false
    end;
is_handler_valid(Id, yaws_logger_sysloggerl, [{syslog_loglevel, L}|Rest]) ->
    case syslog:is_loglevel_valid(L) of
        true ->
            is_handler_valid(Id, yaws_logger_sysloggerl, Rest);
        false ->
            ?ERROR("Handler '~p': invalid syslog level ~p~n", [Id, L]),
            false
    end;

%% Check lager handler options
is_handler_valid(Id, yaws_logger_lager, [{lager_loglevel, L}|Rest]) ->
    case lists:member(L, lager_util:levels()) of
        true ->
            is_handler_valid(Id, yaws_logger_lager, Rest);
        false ->
            ?ERROR("Handler '~p': invalid lager level ~p~n", [Id, L]),
            false
    end;

%% Remaining parameters are invalid
is_handler_valid(Id, _Backend, [Param|_]) ->
    ?ERROR("Handler '~p': bad parameter ~p~n", [Id, Param]),
    false.


%% ----
-spec set_param(atom(), any()) -> ok.

set_param(Param, Value) ->
    application:set_env(?APPLICATION, Param, Value).

%% ----
-spec check_and_set_param(atom(), any()) -> ok | error.

check_and_set_param(Param, Value) ->
    %% If the value is invalid, this function logs an error through
    %% ?WARN/2 but always returns 'ok'. To check a value
    %% programmatically, use the is_param_valid/2 function.
    case is_param_valid(Param, Value) of
        true  -> set_param(Param, Value), ok;
        false -> log_param_errors([Param]), error
    end.

%% ----
-spec show_params() -> ok.

show_params() ->
    Fun = fun(Param) ->
                  Value = get_param(Param),
                  io:format("  * ~s: ~p~n", [Param, Value])
          end,
    lists:foreach(Fun, params_list()).

%% ----
-spec check_params() -> boolean().

check_params() ->
    Fun = fun(Param) ->
                  Value = get_param(Param),
                  not is_param_valid(Param, Value)
          end,
    Bad_Params = lists:filter(Fun, params_list()),
    case Bad_Params of
        [] ->
            true;
        _ ->
            log_param_errors(Bad_Params),
            false
    end.

%% ----
-spec log_param_errors([atom()]) -> ok.

log_param_errors([]) ->
    ok;
log_param_errors([handlers = Param | Rest]) ->
    ?WARN("invalid value for \"~s\": ~p.~n", [Param, get_param(Param)]),
    log_param_errors(Rest);
log_param_errors([Param | Rest]) ->
    ?WARN("unknown parameter \"~s\".~n", [Param]),
    log_param_errors(Rest).


%% ===================================================================
%% application(3erl) callbacks.
%% ===================================================================
start(_, _) ->
    case check_params() of
        true ->
            case yaws_logger_sup:start_link() of
                {ok, Pid} -> {ok, Pid};
                Else      -> Else
            end;
        false ->
            ?ERROR("invalid application configuration~n"),
            {error, invalid_configuration}
    end.

%% ----
prep_stop(State) ->
    State.

%% ----
stop(_) ->
    ok.

%% ----
config_change(_, _, _) ->
    ok.


%%====================================================================
%% API
%%====================================================================
-spec backends() -> [atom()].

backends() ->
    [
     yaws_logger_console,
     yaws_logger_file,
     yaws_logger_sysloggerl,
     yaws_logger_lager
    ].

%% ----
-spec types() -> [atom()].

types() ->
    [any, access, auth].


%%====================================================================
%% Internal functions
%%====================================================================
