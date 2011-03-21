%% $Id$
-module(yaws_logger_app).
-vsn('$Revision$ ').

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
         set_loglevel/1,
         set_parsed_logformat/1,
         get_parsed_logformat/0
        ]).

%% Application callbacks
-export([start/2, stop/1, config_change/3]).

%% ===================================================================
%% Configuration API.
%% ===================================================================

-spec params_list() -> [atom()].

params_list() ->
    [
     access_logformat,
     syslog_loglevel,
     syslog_facility
    ].

-spec get_param(atom()) -> term().

get_param(Param) ->
    {ok, Value} = application:get_env(?APPLICATION, Param),
    Value.

-spec is_param_valid(atom(), term()) -> boolean().

is_param_valid(_Param, '$MANDATORY') ->
    false;
is_param_valid(access_logformat, Value) ->
    (Value =:= default orelse is_list(Value));
is_param_valid(syslog_loglevel, Value) ->
    syslog:is_loglevel_valid(Value);
is_param_valid(syslog_facility, Value) ->
    syslog:is_facility_valid(Value);
is_param_valid(_Param, _Value) ->
    false.

-spec set_param(atom(), term()) -> ok.

set_param(Param, Value) ->
    application:set_env(?APPLICATION, Param, Value).

-spec check_and_set_param(atom(), term()) -> ok.

check_and_set_param(Param, Value) ->
    %% If the value is invalid, this function logs an error through
    %% error_logger:warning_msg/2 but always returns 'ok'. To check a
    %% value programmatically, use the is_param_valid/2 function.
    case is_param_valid(Param, Value) of
        true  -> set_param(Param, Value);
        false -> log_param_errors([Param])
    end.

-spec show_params() -> ok.

show_params() ->
    Fun = fun(Param) ->
        Value = get_param(Param),
        io:format("~s: ~p~n", [Param, Value])
    end,
    lists:foreach(Fun, params_list()).

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

-spec log_param_errors([atom()]) -> ok.

log_param_errors([]) ->
    ok;
log_param_errors([access_logformat = Param | Rest]) ->
    error_logger:warning_msg(
      "~s: invalid value for \"~s\": ~p.~n"
      "It must be a string or default.~n",
      [?APPLICATION, Param, get_param(Param)]),
    log_param_errors(Rest);
log_param_errors([syslog_loglevel = Param | Rest]) ->
    error_logger:warning_msg(
      "~s: invalid value for \"~s\": ~p.~n"
      "It must be the name of a syslog level (atom).~n",
      [?APPLICATION, Param, get_param(Param)]),
    log_param_errors(Rest);
log_param_errors([syslog_facility = Param | Rest]) ->
    error_logger:warning_msg(
      "~s: invalid value for \"~s\": ~p.~n"
      "It must be the name of a syslog facility (atom).~n",
      [?APPLICATION, Param, get_param(Param)]),
    log_param_errors(Rest);
log_param_errors([Param | Rest]) ->
    error_logger:warning_msg(
      "~s: unknown parameter \"~s\".~n",
      [?APPLICATION, Param]),
    log_param_errors(Rest).

%% ===================================================================
%% application(3erl) callbacks.
%% ===================================================================

-spec start(normal | {takeover, atom()} | {failover, atom()}, term()) ->
    {ok, pid()} | {error, term()}.

start(_, _) ->
    Steps = [
      check_params,
      parse_logformat,
      setup_syslog
    ],
    case do_start(Steps) of
        {error, Reason, Message} ->
            Log = case application:get_env(kernel, error_logger) of
                {ok, {file, File}} -> "Check log file \"" ++ File ++ "\".";
                {ok, tty}          -> "Check standard output.";
                _                  -> "No log configured..."
            end,
            %% The following message won't be visible if Erlang was
            %% detached from the terminal.
            io:format(standard_error, "ERROR: ~s~s~n~n", [Message, Log]),
            error_logger:error_msg(Message),
            {error, Reason};
        Ret ->
            Ret
    end.

-spec do_start([term()]) ->
    {ok, pid()} |
    ignore      |
    {error, {already_started, pid()} | shutdown | term()} |
    {error, atom(), term()}.

do_start([check_params | Rest]) ->
    case check_params() of
        true ->
            do_start(Rest);
        false ->
            Message = io_lib:format(
              "~s: invalid application configuration~n", [?APPLICATION]),
            {error, invalid_configuration, Message}
    end;
do_start([parse_logformat | Rest]) ->
    case set_parsed_logformat(get_param(access_logformat)) of
        {ok, _}                  -> do_start(Rest);
        {error, badarg, Message} -> {error, badarg, Message}
    end;
do_start([setup_syslog | Rest]) ->
    %% Add yaws_logger ident in syslog:
    %% default level = info
    Facility = get_param(syslog_facility),
    syslog:add(yaws_logger, "yaws_logger", Facility, info, [log_pid]),

    %% Create the syslog wrapper for yaws_logger
    set_loglevel(get_param(syslog_loglevel)),

    do_start(Rest);
do_start([]) ->
    yaws_logger_sup:start_link().

-spec stop(term()) -> ok.

stop(_) ->
    ?INFO("application yaws_logger stopped", []),

    %% Remove syslog entry for yaws_logger
    syslog:remove(yaws_logger),
    ok.

-spec config_change([{atom(), term()}], [{atom(), term()}], [atom()]) -> ok.

config_change(_, _, _) ->
    ok.

%%====================================================================
%% Application callbacks
%%====================================================================

set_loglevel(Level) ->
    case syslog:is_loglevel_valid(Level) of
        true ->
            syslog_wrapper:create(yaws_logger_log, yaws_logger, Level);
        false ->
            false
    end.


set_parsed_logformat(default) ->
    set_parsed_logformat("%a %l %u %t \"%r\" %s %b \"%{Referer}i\""
                        " \"%{User-Agent}i\" %T %v");
set_parsed_logformat(Fmt) ->
    try
        PFmt = yaws_customlog:parse(Fmt),
        set_param(parsed_access_logformat, PFmt),
        {ok, PFmt}
    catch
        throw:{error, Col, Msg} ->
            Message = io_lib:format(
                        "~s: error in access logoformat at column ~p: ~s~n",
                        [?APPLICATION, Col, Msg]),
            {error, badarg, Message}
    end.


get_parsed_logformat() ->
    case application:get_env(?APPLICATION, parsed_access_logformat) of
        {ok, PFmt} ->
            PFmt;
        undefined ->
            case set_parsed_logformat(get_param(access_logformat)) of
                {ok, PFmt}         -> PFmt;
                {error, badarg, _} -> []
            end
    end.

%%====================================================================
%% Internal functions
%%====================================================================

