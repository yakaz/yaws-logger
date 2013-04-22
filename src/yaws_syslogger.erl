-module(yaws_syslogger).

-behaviour(yaws_logger).

-include_lib("yaws/include/yaws.hrl").
-include_lib("yaws/include/yaws_api.hrl").
-include_lib("kernel/include/inet.hrl").
-include("yaws_syslogger.hrl").

%% API
-export([
         open_log/3,
         close_log/3,
         wrap_log/4,
         write_log/4
        ]).


-type access_data() :: {inet:ip_address() | string(), #http_request{}, #headers{},
                        #outh{}, non_neg_integer()}.

-type auth_data() :: {inet:ip_address() | string(), string(), string()}.

%% ===================================================================
%% Public API.
%% ===================================================================
-spec open_log(string(), auth | access, string()) -> {true, string()}.

open_log(ServerName, Type, _Dir) ->
    Ident    = ident(ServerName, Type),
    Facility = yaws_syslogger_app:get_param(syslog_facility),
    syslog:add(Ident, Ident, Facility, info, []),
    io:format("~p added into yaws_syslogger", [Ident]),
    {true, Ident}.


-spec close_log(any(), auth | access, string()) -> ok.

close_log(_ServerName, _Type, Ident) ->
    syslog:remove(Ident),
    ok.


-spec wrap_log(string(), auth | access, string(), non_neg_integer()) -> ok.

wrap_log(_, _, Data, _) ->
    Data.


-spec write_log(string(), auth | access, string(),
                access_data() | auth_data()) -> ok.

write_log(ServerName, access, Ident, {Ip, Req, InH, OutH, Time}) ->
    LogMsg = format_accesslog(ServerName, Ip, Req, InH, OutH, Time),
    syslog:info_msg(Ident, LogMsg, []),
    ok;
write_log(ServerName, auth, Ident, {Ip, Path,Item}) ->
    LogMsg = format_authlog(ServerName, Ip, Path, Item),
    syslog:info_msg(Ident, LogMsg, []),
    ok;
write_log(_, _, _, _) ->
    ok.




%%====================================================================
%% Internal functions
%%====================================================================
-spec ident(string(), atom()) -> string().

ident(ServerName, Type) ->
    ServerName ++ "_" ++ atom_to_list(Type).


%%====================================================================
-spec format_accesslog(string(), inet:ip_address() | string(), #http_request{},
                       #headers{}, #outh{}, non_neg_integer()) -> string().

format_accesslog(ServerName, Ip, Req, InH, OutH, Time) ->
    Fmt = yaws_syslogger_app:get_parsed_logformat(),
    format_accesslog(Fmt, ServerName, Ip, Req, InH, OutH, Time, []).


-spec format_accesslog(list(), string(), inet:ip_address() | string(),
                       #http_request{}, #headers{}, #outh{}, non_neg_integer(),
                       string()) -> string().

format_accesslog([], _, _, _, _, _, _, LogMsg) ->
    lists:flatten(lists:reverse(LogMsg));
format_accesslog([{remote_ip, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [format_ip(Ip)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{real_remote_ip, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [format_real_ip(Ip,InH)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{response_length, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_response_length(Req, OutH)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{ms_time, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [integer_to_list(Time)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{request_protocol, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_http_version(Req)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{remote_host, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [format_host(Ip)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{remote_name, _Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = ["-"|LogMsg],
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{request_method, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_request_method(Req)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{pid, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [pid_to_list(self())|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{query_string, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_query_string(Req)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{request, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_request(Req)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{status, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_request_status(OutH)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{date, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [format_now(now())|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{time, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [integer_to_list(Time div 1000000)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{user, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_auth_user(InH)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{url_path, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_request_url(Req)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{servername, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [ServerName|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{{cookie, Name}, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_cookie_val(Name, InH)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{{request_header, Name}, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_request_header(Name, InH)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{{response_header, Name}, Cond}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = case check_cond(Cond, OutH#outh.status) of
                  true  -> [get_response_header(Name, OutH)|LogMsg];
                  false -> ["-"|LogMsg]
              end,
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1);
format_accesslog([{char, C}|Rest],
                 ServerName, Ip, Req, InH, OutH, Time, LogMsg) ->
    LogMsg1 = [[C]|LogMsg],
    format_accesslog(Rest, ServerName, Ip, Req, InH, OutH, Time, LogMsg1).




-spec check_cond(none | {match, list()} | {nomatch, list()}, pos_integer()) ->
    boolean().

check_cond(none, _) ->
    true;
check_cond({match, Cond}, Status) ->
    lists:member(Status, Cond);
check_cond({nomatch, Cond}, Status) ->
    not lists:member(Status, Cond).


%%====================================================================
-spec format_authlog(string(), inet:ip_address() | string(), string(),
                     string()) ->
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


%%====================================================================
-spec format_ip(inet:ip_address() | undefined | string()) -> string().

format_ip(Ip) when is_tuple(Ip) ->
    inet_parse:ntoa(Ip);
format_ip(undefined) ->
    "0.0.0.0";
format_ip(HostName) ->
    HostName.


-spec format_host(inet:ip_address() | undefined | string()) -> string().

format_host(Ip) when is_tuple(Ip); is_list(Ip) ->
    case inet:gethostbyaddr(Ip) of
        {ok, H} -> element(2, H);
        _       -> format_ip(Ip)
    end;
format_host(undefined) ->
    "0.0.0.0".


%%====================================================================
-spec format_real_ip(inet:ip_address() | string(), #headers{}) ->
    string().

format_real_ip(Ip, InH) when is_tuple(Ip) ->
    case is_whitelisted_revproxy(Ip) of
        true ->
            case yaws:split_sep(InH#headers.x_forwarded_for, $,) of
                [FirstIp|_Proxies] -> FirstIp;
                []                 -> inet_parse:ntoa(Ip)
            end;
        false ->
            inet_parse:ntoa(Ip)
    end;
format_real_ip(HostName, InH) ->
    try
        Ip = yaws_syslogger_netutils:parse_ip(HostName),
        format_real_ip(Ip, InH)
    catch
        _:_ ->
            HostName
    end.


-spec is_whitelisted_revproxy(inet:ip_address()) -> boolean().

is_whitelisted_revproxy(Ip) ->
    RevWList = yaws_syslogger_app:get_parsed_revproxy_whitelist(),
    is_whitelisted_revproxy(Ip, RevWList).

is_whitelisted_revproxy(_Ip, []) ->
    false;
is_whitelisted_revproxy(Ip, [IpRange|Rest]) ->
    case yaws_syslogger_netutils:match_ip(Ip, IpRange) of
        true  -> true;
        false -> is_whitelisted_revproxy(Ip, Rest)
    end.



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
        {abs_path, P} ->
            case catch yaws_api:url_decode_q_split(P) of
                {'EXIT', _} -> "/undecodable_path";
                {Path, _}   -> Path
            end;
        _ ->
            "/undecodable_path"
    end.


-spec get_query_string(#http_request{}) -> string().

get_query_string(Req) ->
    case Req#http_request.path of
        {abs_path, P} ->
            case catch yaws_api:url_decode_q_split(P) of
                {'EXIT', _}  -> [];
                {_, QString} -> QString
            end;
        _ ->
            []
    end.


-spec get_request(#http_request{}) -> string().

get_request(Req) ->
    Meth = get_request_method(Req),
    Ver  = get_http_version(Req),
    Path = case Req#http_request.path of
               {abs_path, P} ->
                   case catch yaws_api:url_decode(P) of
                       {'EXIT', _} -> "/undecodable_path";
                       Val         -> Val
                   end;
               _ ->
                   "/undecodable_path"
           end,
    no_ctl([Meth, $\s, Path, $\s, Ver]).




-spec get_http_version(#http_request{}) -> string().

get_http_version(Req) ->
    case Req#http_request.version of
        {1,0} -> "HTTP/1.0";
        {1,1} -> "HTTP/1.1";
        {0,9} -> "HTTP/0.9"
    end.

-spec get_auth_user(#headers{}) -> string().

get_auth_user(InH) ->
    case InH#headers.authorization of
        {U, _P, _OStr} when is_list(U) -> U;
        _                              -> "-"
    end.


-spec get_cookie_val(string(), #headers{}) -> string().

get_cookie_val(Name, InH) ->
    yaws_api:find_cookie_val(Name, InH#headers.cookie).


-spec get_request_header(string(), #headers{}) -> string().

get_request_header(Name, InH) ->
    case Name of
        "connection" ->
            header_to_string(InH#headers.connection);
        "accept" ->
            header_to_string(InH#headers.accept);
        "host" ->
            header_to_string(InH#headers.host);
        "if-modified-since" ->
            header_to_string(InH#headers.if_modified_since);
        "if-match" ->
            header_to_string(InH#headers.if_match);
        "if-none-match" ->
            header_to_string(InH#headers.if_none_match);
        "if-range" ->
            header_to_string(InH#headers.if_range);
        "if-unmodified-since" ->
            header_to_string(InH#headers.if_unmodified_since);
        "range" ->
            header_to_string(InH#headers.range);
        "referer" ->
            header_to_string(InH#headers.referer);
        "user-agent" ->
            header_to_string(InH#headers.user_agent);
        "accept-ranges" ->
            header_to_string(InH#headers.accept_ranges);
        "keep-alive" ->
            header_to_string(InH#headers.keep_alive);
        "location" ->
            header_to_string(InH#headers.location);
        "content-length" ->
            header_to_string(InH#headers.content_length);
        "content-type" ->
            header_to_string(InH#headers.content_type);
        "content-encoding" ->
            header_to_string(InH#headers.content_encoding);
        "authorization" ->
            case InH#headers.authorization of
                {_, _, Orig} -> header_to_string(Orig);
                _            -> "-"
            end;
        "transfer-encoding" ->
            header_to_string(InH#headers.transfer_encoding);
        "x-forwarded-for" ->
            header_to_string(InH#headers.x_forwarded_for);
        _ ->
            case lists:keysearch(Name, 3, InH#headers.other) of
                {value, {http_header, _, _, _, Val}} -> header_to_string(Val);
                false                                -> "-"
            end
    end.


-spec get_response_length(#http_request{}, #outh{}) -> string().

get_response_length(Req, OutH) ->
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


-spec get_response_header(string(), #outh{}) -> string().

get_response_header(Name, OutH) ->
    case Name of
        "status" ->
            header_to_string(OutH#outh.status);
        "connection" ->
            header_to_string(OutH#outh.connection);
        "server" ->
            header_to_string(OutH#outh.server);
        "location" ->
            header_to_string(OutH#outh.location);
        "cache-control" ->
            header_to_string(OutH#outh.cache_control);
        "expires" ->
            header_to_string(OutH#outh.expires);
        "date" ->
            header_to_string(OutH#outh.date);
        "allow" ->
            header_to_string(OutH#outh.allow);
        "last-modified" ->
            header_to_string(OutH#outh.last_modified);
        "etag" ->
            header_to_string(OutH#outh.etag);
        "content-range" ->
            header_to_string(OutH#outh.content_range);
        "content-length" ->
            header_to_string(OutH#outh.content_length);
        "content-type" ->
            header_to_string(OutH#outh.content_type);
        "content-encoding" ->
            header_to_string(OutH#outh.content_encoding);
        "transfer-encoding" ->
            header_to_string(OutH#outh.transfer_encoding);
        "www-authenticate" ->
            header_to_string(OutH#outh.www_authenticate);
        _ ->
            "-"
    end.


-spec header_to_string(integer() | atom() | string() | undefined) ->
    string().

header_to_string(undefined) -> "-";
header_to_string(N) when is_integer(N) -> N;
header_to_string(A) when is_atom(A)    -> A;
header_to_string(S) when is_list(S)    -> S.



-spec no_ctl(string()) -> string().

no_ctl([H|T]) when H < 32 ->
    no_ctl(T);
no_ctl([H|T]) ->
    [H|no_ctl(T)];
no_ctl([]) ->
    [].
