%% $Id$
-module(yaws_logger).
-vsn('$Revision$ ').

-behaviour(yaws_alog).

-include_lib("yaws/include/yaws.hrl").
-include_lib("yaws/include/yaws_api.hrl").
-include_lib("kernel/include/inet.hrl").
-include("yaws_logger.hrl").

%% API
-export([
         open_alog/3,
         close_alog/3,
         wrap_alog/4,
         write_alog/4
        ]).


-type access_data() :: {ip_address() | string(), #http_request{}, #headers{},
                        #outh{}, non_neg_integer()}.

-type auth_data() :: {ip_address() | string(), string(), string()}.

%% ===================================================================
%% Public API.
%% ===================================================================
-spec open_alog(string(), auth | access, string()) -> {true, string()}.

open_alog(ServerName, Type, _Dir) ->
    Ident    = ident(ServerName, Type),
    Facility = yaws_logger_app:get_param(syslog_facility),
    syslog:add(Ident, Ident, Facility, info, []),
    io:format("~p added into yaws_logger", [Ident]),
    {true, Ident}.


-spec close_alog(any(), auth | access, string()) -> ok.

close_alog(_ServerName, _Type, Ident) ->
    syslog:remove(Ident),
    ok.


-spec wrap_alog(string(), auth | access, string(), non_neg_integer()) -> ok.

wrap_alog(_, _, _, _) ->
    ok.


-spec write_alog(string(), auth | access, string(),
                 access_data() | auth_data()) -> ok.

write_alog(ServerName, access, Ident, {Ip, Req, InH, OutH, Time}) ->
    LogMsg = format_accesslog(ServerName, Ip, Req, InH, OutH, Time),
    syslog:info_msg(Ident, LogMsg, []),
    ok;
write_alog(ServerName, auth, Ident, {Ip, Path,Item}) ->
    LogMsg = format_authlog(ServerName, Ip, Path, Item),
    syslog:info_msg(Ident, LogMsg, []),
    ok;
write_alog(_, _, _, _) ->
    ok.




%%====================================================================
%% Internal functions
%%====================================================================
-spec ident(string(), atom()) -> string().

ident(ServerName, Type) ->
    ServerName ++ "_" ++ atom_to_list(Type).


%%====================================================================
-spec format_accesslog(string(), ip_address() | string(), #http_request{},
                       #headers{}, #outh{}, non_neg_integer()) -> string().

format_accesslog(ServerName, Ip, Req, InH, OutH, Time) ->
    Now       = now(),
    Status    = get_request_status(OutH),
    Meth      = get_request_method(Req),
    Path      = get_request_url(Req),
    Ver       = get_http_version(Req),
    Len       = get_response_size(Req, OutH),
    Referer   = get_http_header(InH, referer),
    UserAgent = get_http_header(InH, user_agent),
    User      = get_auth_user(InH),
    I = [format_ip(Ip), " - ", User, [$\s], format_now(Now), [$\s, $"],
         no_ctl([Meth, $\s, Path, $\s, Ver]), [$",$\s], Status,
         [$\s], Len, [$\s,$"], Referer, [$",$\s,$"], UserAgent,
         [$",$\s], format_time(Time), [$\s], ServerName, [$\n]],
    lists:flatten(I).


-spec format_authlog(string(), ip_address() | string(), string(), string()) ->
    string().

format_authlog(ServerName, Ip, Path, Item) ->
    IpStr = case catch inet_parse:ntoa(Ip) of
                {'EXIT', _} -> "unknownip";
                Val -> Val
            end,
    Msg = case Item of
              {ok, User}       -> ["OK user=", User];
              403              -> ["403"];
              {401, Realm}     -> ["401 realm=", Realm];
              {401, User, PWD} -> ["401 user=", User, " badpwd=", PWD]
          end,
    I = [IpStr, [$\s], format_now(now()), [$\s], ServerName, [$\s, $"], Path,
         [$",$\s], Msg, [$\s]],
    lists:flatten(I).


-spec no_ctl(string()) -> string().

no_ctl([H|T]) when H < 32 ->
    no_ctl(T);
no_ctl([H|T]) ->
    [H|no_ctl(T)];
no_ctl([]) ->
    [].


-spec format_ip(ip_address() | undefined | string()) -> string().

format_ip(Ip) when is_tuple(Ip) ->
    inet_parse:ntoa(Ip);
format_ip(undefined) ->
    "0.0.0.0";
format_ip(HostName) ->
    HostName.



-spec format_time(non_neg_integer()) -> string().

format_time(Time) ->
    integer_to_list(Time div 1000000).

%%====================================================================
-spec format_now({non_neg_integer(),non_neg_integer(),non_neg_integer()}) ->
    iolist().

format_now(Now) ->
    LocalTime = calendar:now_to_local_time(Now),
    {{Year, Month, Day}, {Hour, Min, Sec}} = LocalTime,
    ["[",fill_zero(Day,2),"/",yaws:month(Month),"/",integer_to_list(Year),
     ":",fill_zero(Hour,2),":",fill_zero(Min,2),":",fill_zero(Sec,2),
     " ",zone(LocalTime),"]"].


-spec zone({{non_neg_integer(), 1..12, 1..31}, {0..23, 0..59, 0..59}}) ->
    iolist().

zone(LocalTime) ->
    UTime    = erlang:universaltime(),
    DiffSecs = calendar:datetime_to_gregorian_seconds(LocalTime) -
        calendar:datetime_to_gregorian_seconds(UTime),
    zone(DiffSecs div 3600, (DiffSecs rem 3600) div 60).


-spec zone(integer(), integer()) -> iolist().

zone(Hr, Min) when Hr < 0; Min < 0 ->
    [$-, fill_zero(abs(Hr), 2), fill_zero(abs(Min), 2)];
zone(Hr, Min) when Hr >= 0, Min >= 0 ->
    [$+, fill_zero(abs(Hr), 2), fill_zero(abs(Min), 2)].


-spec fill_zero(non_neg_integer(), non_neg_integer()) -> string().

fill_zero(N, Width) ->
    left_fill(N, Width, $0).


-spec left_fill(non_neg_integer() | string(), non_neg_integer(), char()) ->
    string().

left_fill(N, Width, Fill) when is_integer(N) ->
    left_fill(integer_to_list(N), Width, Fill);
left_fill(N, Width, _Fill) when length(N) >= Width ->
    N;
left_fill(N, Width, Fill) ->
    left_fill([Fill|N], Width, Fill).


%%====================================================================
-spec get_request_status(#outh{}) -> string().

get_request_status(OutH) ->
    case OutH#outh.status of
        undefined -> "-";
        S         -> integer_to_list(S)
    end.


-spec get_request_method(#http_request{}) -> string().

get_request_method(Req) ->
    atom_to_list(Req#http_request.method).


-spec get_request_url(#http_request{}) -> string().

get_request_url(Req) ->
    case Req#http_request.path of
        {abs_path, Path} ->
            case catch yaws_api:url_decode(Path) of
                {'EXIT', _} -> "/undecodable_path";
                Val         -> Val
            end;
        _ ->
            "/undecodable_path"
    end.


-spec get_http_version(#http_request{}) -> string().

get_http_version(Req) ->
    case Req#http_request.version of
        {1,0} -> "HTTP/1.0";
        {1,1} -> "HTTP/1.1";
        {0,9} -> "HTTP/0.9"
    end.

-spec get_response_size(#http_request{}, #outh{}) -> string().

get_response_size(Req, OutH) ->
    case Req#http_request.method of
        'HEAD' ->
            "-";
        _ ->
            case OutH#outh.contlen of
                undefined ->
                    case OutH#outh.act_contlen of
                        undefined -> "-";
                        L         -> integer_to_list(L)
                    end;
                L ->
                    integer_to_list(L)
            end
    end.

-spec get_auth_user(#headers{}) -> string().

get_auth_user(InH) ->
    case InH#headers.authorization of
        {U, _P, _OStr} -> U;
        _              -> "-"
    end.


-spec get_http_header(#headers{}, atom()) -> string().

get_http_header(InH, HName) ->
    if
        HName =:= referer ->
            header_to_string(InH#headers.referer);
        HName =:= user_agent ->
            header_to_string(InH#headers.user_agent);
        true ->
            "-"
    end.


-spec header_to_string(string() | undefined) -> string().

header_to_string(undefined) -> "-";
header_to_string(Header)    -> Header.
