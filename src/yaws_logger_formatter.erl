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

-module(yaws_logger_formatter).

-include_lib("yaws/include/yaws.hrl").
-include_lib("yaws/include/yaws_api.hrl").
-include_lib("kernel/include/inet.hrl").

%% API
-export([
         parse_accesslog_format/1,
         parse_revproxy_whitelist/1,
         accesslog/4, authlog/2]).

-define(COMMON_LOG_FORMAT,   "%h %l %u %t \"%r\" %s %b").
-define(COMBINED_LOG_FORMAT, ?COMMON_LOG_FORMAT ++ " \"%{Referer}i\" \"%{User-Agent}i\"").
-define(DEFAULT_FORMAT,      ?COMBINED_LOG_FORMAT ++ " %D %v").

%%====================================================================
%% API
%%====================================================================
-spec parse_accesslog_format(Format) -> ParsedFmt when
      Format    :: default | common | combined | list(),
      ParsedFmt :: [tuple()].

parse_accesslog_format(default) ->
    parse_accesslog_format(?DEFAULT_FORMAT);
parse_accesslog_format(common) ->
    parse_accesslog_format(?COMMON_LOG_FORMAT);
parse_accesslog_format(combined) ->
    parse_accesslog_format(?COMBINED_LOG_FORMAT);
parse_accesslog_format(Fmt) ->
    parse_accesslog_format(Fmt, 0, []).


%% ----
-spec parse_revproxy_whitelist(list()) -> list().

parse_revproxy_whitelist([]) ->
    [];
parse_revproxy_whitelist([Str|Rest]) ->
    [yaws_logger_netutils:parse_ip(Str)|parse_revproxy_whitelist(Rest)].


%% ----
-spec accesslog(Fmt, ServerName, RevPx, Data) -> Str when
      Fmt        :: [tuple()],
      ServerName :: string(),
      RevPx      :: list(),
      Data       :: {Ip, Req, InH, OutH, Time},
      Ip         :: inet:ip_address() | inet:hostname() | unknown,
      Req        :: #http_request{},   %% defined in yaws_api.hrl
      InH        :: #headers{},        %% defined in yaws_api.hrl
      OutH       :: #outh{},           %% defined in yaws.hrl
      Time       :: non_neg_integer(), %% The microseconds to serve the request
      Str        :: string().

accesslog(Fmt, ServerName, RevPx, Data) ->
    format_accesslog(Fmt, ServerName, RevPx, Data, []).


%% ----
-spec authlog(ServerName, Data) -> Str when
      ServerName :: string(),
      Data       :: {Ip, Path, Item},
      Ip         :: inet:ip_address() | inet:hostname() | unknown,
      Path       :: string(),
      Item       :: {ok, User} | 403 | {401, Realm},
      User       :: string(),
      Realm      :: string(),
      Str        :: string().

authlog(ServerName, {Ip, Path, Item}) ->
    IpStr = case catch inet_parse:ntoa(Ip) of
                {'EXIT', _} -> "unknownip";
                Val -> Val
            end,
    Msg = case Item of
              {ok, User}       -> ["OK user=", User];
              403              -> ["403"];
              {401, Realm}     -> ["401 realm=", Realm];
              {401, User, PWD} -> ["401 user=", User, " badpwd=", PWD];
              Str              -> Str
          end,
    I = [IpStr, [$\s], format_ts(os:timestamp()), [$\s], ServerName, [$\s, $"],
         Path, [$",$\s], Msg, [$\s]],
    lists:flatten(I).

%%====================================================================
%% Internal functions
%%====================================================================
parse_accesslog_format([], _, Tokens) ->
    lists:reverse(Tokens);
parse_accesslog_format([$%,$%|Rest], Col, Tokens) ->
    parse_accesslog_format(Rest, Col+2, [{char, $%}|Tokens]);
parse_accesslog_format([$%|Rest], Col, Tokens) ->
    {Cond,  Col1, Rest1} = parse_accesslog_cond(Rest, Col+1),
    {Token, Col2, Rest2} =
        case Rest1 of
            [$a|R] -> {remote_ip,           Col1+1, R};
            [$B|R] -> {response_length,     Col1+1, R};
            [$b|R] -> {clf_response_length, Col1+1, R};
            [$D|R] -> {ms_time,             Col1+1, R};
            [$H|R] -> {request_protocol,    Col1+1, R};
            [$h|R] -> {remote_host,         Col1+1, R};
            [$l|R] -> {remote_name,         Col1+1, R};
            [$m|R] -> {request_method,      Col1+1, R};
            [$P|R] -> {pid,                 Col1+1, R};
            [$q|R] -> {query_string,        Col1+1, R};
            [$r|R] -> {request,             Col1+1, R};
            [$s|R] -> {status,              Col1+1, R};
            [$t|R] -> {date,                Col1+1, R};
            [$T|R] -> {time,                Col1+1, R};
            [$u|R] -> {user,                Col1+1, R};
            [$U|R] -> {url_path,            Col1+1, R};
            [$v|R] -> {servername,          Col1+1, R};
            [${|R] -> parse_accesslog_var(R, Col1+1);
            [C|_]  -> throw({error, Col1, "unknown log directive %" ++ [C]});
            []     -> throw({error, Col1, "premature end log format"})
        end,
    parse_accesslog_format(Rest2, Col2, [{Token, Cond}|Tokens]);
parse_accesslog_format([C|Rest], Col, Tokens) ->
    parse_accesslog_format(Rest, Col+1, [{char, C}|Tokens]).


parse_accesslog_cond([$!|Rest], Col) ->
    case parse_accesslog_cond1(Rest, Col+1, []) of
        {[], Col1, Rest1}   -> {none,            Col1, Rest1};
        {Cond, Col1, Rest1} -> {{nomatch, Cond}, Col1, Rest1}
    end;
parse_accesslog_cond(Rest, Col) ->
    case parse_accesslog_cond1(Rest, Col+1, []) of
        {[], Col1, Rest1}   -> {none,          Col1, Rest1};
        {Cond, Col1, Rest1} -> {{match, Cond}, Col1, Rest1}
    end.


parse_accesslog_cond1([$1,$0,X|Rest], Col, Cond) when X >= $0, X =< $1 ->
    parse_accesslog_cond2(Rest, Col+3, [list_to_integer([$1,$0,X])|Cond]);
parse_accesslog_cond1([$2,$0,X|Rest], Col, Cond) when X >= $0, X =< $6 ->
    parse_accesslog_cond2(Rest, Col+3, [list_to_integer([$2,$0,X])|Cond]);
parse_accesslog_cond1([$3,$0,X|Rest], Col, Cond) when X >= $0, X =< $7 ->
    parse_accesslog_cond2(Rest, Col+3, [list_to_integer([$3,$0,X])|Cond]);
parse_accesslog_cond1([$4,$0,X|Rest], Col, Cond) when X >= $0, X =< $9 ->
    parse_accesslog_cond2(Rest, Col+3, [list_to_integer([$4,$0,X])|Cond]);
parse_accesslog_cond1([$4,$1,X|Rest], Col, Cond) when X >= $0, X =< $7 ->
    parse_accesslog_cond2(Rest, Col+3, [list_to_integer([$4,$1,X])|Cond]);
parse_accesslog_cond1([$5,$0,X|Rest], Col, Cond) when X >= $0, X =< $5 ->
    parse_accesslog_cond2(Rest, Col+3, [list_to_integer([$4,$1,X])|Cond]);
parse_accesslog_cond1(Rest, Col, Cond) ->
    {Cond, Col, Rest}.


parse_accesslog_cond2([$,|Rest], Col, Cond) ->
    parse_accesslog_cond1(Rest, Col+1, Cond);
parse_accesslog_cond2(Rest, Col, Cond) ->
    {Cond, Col, Rest}.

parse_accesslog_var(Rest, Col) ->
    parse_accesslog_var(Rest, Col, []).

parse_accesslog_var([], Col, Var) ->
    throw({error, Col, "variable '" ++ lists:reverse(Var) ++ "' not terminated"});
parse_accesslog_var([$},$C|Rest], Col, Var) ->
    {{cookie, lists:reverse(Var)}, Col+2, Rest};
parse_accesslog_var([$},$i|Rest], Col, Var) ->
    {{request_header, string:to_lower(lists:reverse(Var))}, Col+2, Rest};
parse_accesslog_var([$},$o|Rest], Col, Var) ->
    {{response_header, string:to_lower(lists:reverse(Var))}, Col+2, Rest};
parse_accesslog_var([$r,$e,$a,$l,$},$a|Rest], Col, []) ->
    {real_remote_ip, Col+6, Rest};
parse_accesslog_var([$r,$e,$a,$l,$},$h|Rest], Col, []) ->
    {real_remote_host, Col+6, Rest};
parse_accesslog_var([C|Rest], Col, Var) ->
    parse_accesslog_var(Rest, Col+1, [C|Var]).


%% ----
format_accesslog([], _, _, _, Msg) ->
    lists:flatten(lists:reverse(Msg));
format_accesslog([{remote_ip, Cond}|Rest], ServerName, RevPx,
                 {Ip,_,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [format_ip(Ip)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{real_remote_ip, Cond}|Rest], ServerName, RevPx,
                 {Ip,_,InH,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [format_real_ip(Ip,InH,RevPx)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{clf_response_length, Cond}|Rest], ServerName, RevPx,
                 {_,Req,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_clf_response_length(Req, OutH)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{response_length, Cond}|Rest], ServerName, RevPx,
                 {_,Req,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_response_length(Req, OutH)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{ms_time, Cond}|Rest], ServerName, RevPx,
                 {_,_,_,OutH,Time}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [integer_to_list(Time)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{request_protocol, Cond}|Rest], ServerName, RevPx,
                 {_,Req,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_http_version(Req)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{remote_host, Cond}|Rest], ServerName, RevPx,
                 {Ip,_,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [format_host(Ip)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{real_remote_host, Cond}|Rest], ServerName, RevPx,
                 {Ip,_,InH,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [format_real_host(Ip,InH,RevPx)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{remote_name, _Cond}|Rest], ServerName, RevPx,
                 Data, Msg) ->
    Msg1 = [$-|Msg],
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{request_method, Cond}|Rest], ServerName, RevPx,
                 {_,Req,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_request_method(Req)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{pid, Cond}|Rest], ServerName, RevPx,
                 {_,_,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [pid_to_list(self())|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{query_string, Cond}|Rest], ServerName, RevPx,
                 {_,Req,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_query_string(Req)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{request, Cond}|Rest], ServerName, RevPx,
                 {_,Req,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_request(Req)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{status, Cond}|Rest], ServerName, RevPx,
                 {_,_,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_request_status(OutH)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{date, Cond}|Rest], ServerName, RevPx,
                 {_,_,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [format_ts(os:timestamp())|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{time, Cond}|Rest], ServerName, RevPx,
                 {_,_,_,OutH,Time}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [integer_to_list(Time div 1000000)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{user, Cond}|Rest], ServerName, RevPx,
                 {_,_,InH,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_auth_user(InH)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{url_path, Cond}|Rest], ServerName, RevPx,
                 {_,Req,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_request_url(Req)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{servername, Cond}|Rest], ServerName, RevPx,
                 {_,_,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [ServerName|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{{cookie, Name}, Cond}|Rest], ServerName, RevPx,
                 {_,_,InH,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_cookie_val(Name, InH)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{{request_header, Name}, Cond}|Rest], ServerName, RevPx,
                 {_,_,InH,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_request_header(Name, InH)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{{response_header, Name}, Cond}|Rest], ServerName, RevPx,
                 {_,_,_,OutH,_}=Data, Msg) ->
    Msg1 = case check_cond(Cond, OutH#outh.status) of
               true  -> [get_response_header(Name, OutH)|Msg];
               false -> [$-|Msg]
           end,
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1);
format_accesslog([{char, C}|Rest], ServerName, RevPx, Data, Msg) ->
    Msg1 = [[C]|Msg],
    format_accesslog(Rest, ServerName, RevPx, Data, Msg1).

%% ----
check_cond(none, _) ->
    true;
check_cond({match, Cond}, Status) ->
    lists:member(Status, Cond);
check_cond({nomatch, Cond}, Status) ->
    not lists:member(Status, Cond).


%% ----
format_ip(Ip) when is_tuple(Ip) ->
    inet_parse:ntoa(Ip);
format_ip(unknown) ->
    "0.0.0.0";
format_ip(undefined) ->
    "0.0.0.0";
format_ip(HostName) ->
    HostName.


format_host(Ip) when is_tuple(Ip); is_list(Ip) ->
    case inet:gethostbyaddr(Ip) of
        {ok, H} -> element(2, H);
        _       -> format_ip(Ip)
    end;
format_host(unknown) ->
    "unknown";
format_host(undefined) ->
    "unknown".


%% ----
format_real_ip(Ip, InH, RevPx) when is_tuple(Ip) ->
    case is_whitelisted_revproxy(Ip, RevPx) of
        true ->
            case yaws:split_sep(InH#headers.x_forwarded_for, $,) of
                [FirstIp|_Proxies] -> FirstIp;
                []                 -> inet_parse:ntoa(Ip)
            end;
        false ->
            inet_parse:ntoa(Ip)
    end;
format_real_ip(unknown, _InH, _RevPx) ->
    "0.0.0.0";
format_real_ip(undefined, _InH, _RevPx) ->
    "0.0.0.0";
format_real_ip(HostName, InH, RevPx) ->
    try
        Ip = yaws_logger_netutils:parse_ip(HostName),
        format_real_ip(Ip, InH, RevPx)
    catch
        _:_ ->
            HostName
    end.

format_real_host(Ip, InH, RevPx) when is_tuple(Ip) ->
    case is_whitelisted_revproxy(Ip, RevPx) of
        true ->
            case yaws:split_sep(InH#headers.x_forwarded_for, $,) of
                [FirstIp|_Proxies] -> format_host(FirstIp);
                []                 -> format_host(Ip)
            end;
        false ->
            format_host(Ip)
    end;
format_real_host(unknown, _InH, _RevPx) ->
    "unknown";
format_real_host(undefined, _InH, _RevPx) ->
    "unknown";
format_real_host(HostName, InH, RevPx) ->
    try
        Ip = yaws_logger_netutils:parse_ip(HostName),
        format_real_host(Ip, InH, RevPx)
    catch
        _:_ ->
            HostName
    end.

is_whitelisted_revproxy(_Ip, []) ->
    false;
is_whitelisted_revproxy(Ip, [IpRange|Rest]) ->
    case yaws_logger_netutils:match_ip(Ip, IpRange) of
        true  -> true;
        false -> is_whitelisted_revproxy(Ip, Rest)
    end.


%% ----
format_ts(TS) ->
    LocalTime = calendar:now_to_local_time(TS),
    {{Year, Month, Day}, {Hour, Min, Sec}} = LocalTime,
    [$[, fill_zero(Day, 2), $/, yaws:month(Month), $/, integer_to_list(Year),
     $:, fill_zero(Hour, 2), $:, fill_zero(Min, 2), $:, fill_zero(Sec, 2),
     $\s, zone(LocalTime), $]].

zone(LocalTime) ->
    UTime    = erlang:universaltime(),
    DiffSecs = calendar:datetime_to_gregorian_seconds(LocalTime) -
        calendar:datetime_to_gregorian_seconds(UTime),
    zone(DiffSecs div 3600, (DiffSecs rem 3600) div 60).

zone(Hr, Min) when Hr < 0; Min < 0 ->
    [$-, fill_zero(abs(Hr), 2), fill_zero(abs(Min), 2)];
zone(Hr, Min) when Hr >= 0, Min >= 0 ->
    [$+, fill_zero(abs(Hr), 2), fill_zero(abs(Min), 2)].

fill_zero(N, Width) ->
    left_fill(N, Width, $0).

left_fill(N, Width, Fill) when is_integer(N) ->
    left_fill(integer_to_list(N), Width, Fill);
left_fill(N, Width, _Fill) when length(N) >= Width ->
    N;
left_fill(N, Width, Fill) ->
    left_fill([Fill|N], Width, Fill).


%% ----
get_request_status(OutH) ->
    case OutH#outh.status of
        undefined -> $-;
        S         -> integer_to_list(S)
    end.

get_request_method(Req) ->
    atom_to_list(Req#http_request.method).

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

get_query_string(Req) ->
    case Req#http_request.path of
        {abs_path, P} ->
            case catch yaws_api:url_decode_q_split(P) of
                {'EXIT', _}  -> [];
                {_, []}      -> [];
                {_, QString} -> [$?, QString]
            end;
        _ ->
            []
    end.

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

get_http_version(Req) ->
    case Req#http_request.version of
        {1,0} -> "HTTP/1.0";
        {1,1} -> "HTTP/1.1";
        {0,9} -> "HTTP/0.9"
    end.

get_auth_user(InH) ->
    case InH#headers.authorization of
        {U, _P, _OStr} when is_list(U) -> U;
        _                              -> $-
    end.

get_cookie_val(Name, InH) ->
    yaws_api:find_cookie_val(Name, InH#headers.cookie).

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
        "cookie" ->
            string:join([header_to_string(C) || C <- InH#headers.cookie],
                        ";");
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
                _            -> $-
            end;
        "transfer-encoding" ->
            header_to_string(InH#headers.transfer_encoding);
        "x-forwarded-for" ->
            header_to_string(InH#headers.x_forwarded_for);
        _ ->
            case lists:keysearch(Name, 3, InH#headers.other) of
                {value, {http_header, _, _, _, Val}} -> header_to_string(Val);
                false                                -> $-
            end
    end.

get_clf_response_length(Req, OutH) ->
    case get_response_length(Req, OutH) of
        $0 -> $-;
        L   -> L
    end.

get_response_length(Req, OutH) ->
    case Req#http_request.method of
        'HEAD' ->
            $0;
        _ ->
            case OutH#outh.contlen of
                undefined ->
                    case OutH#outh.act_contlen of
                        undefined -> $0;
                        L         -> integer_to_list(L)
                    end;
                L ->
                    integer_to_list(L)
            end
    end.

get_response_header(Name, OutH) ->
    case Name of
        "status" ->
            integer_to_list(OutH#outh.status);
        "connection" ->
            header_to_string(Name, OutH#outh.connection);
        "server" ->
            header_to_string(Name, OutH#outh.server);
        "location" ->
            header_to_string(Name, OutH#outh.location);
        "cache-control" ->
            header_to_string(Name, OutH#outh.cache_control);
        "expires" ->
            header_to_string(Name, OutH#outh.expires);
        "date" ->
            header_to_string(Name, OutH#outh.date);
        "allow" ->
            header_to_string(Name, OutH#outh.allow);
        "last-modified" ->
            header_to_string(Name, OutH#outh.last_modified);
        "etag" ->
            header_to_string(Name, OutH#outh.etag);
        "content-range" ->
            header_to_string(Name, OutH#outh.content_range);
        "content-length" ->
            header_to_string(Name, OutH#outh.content_length);
        "content-type" ->
            header_to_string(Name, OutH#outh.content_type);
        "content-encoding" ->
            header_to_string(Name, OutH#outh.content_encoding);
        "transfer-encoding" ->
            header_to_string(Name, OutH#outh.transfer_encoding);
        "www-authenticate" ->
            header_to_string(Name, OutH#outh.www_authenticate);
        _ ->
            header_to_string(Name, OutH#outh.other)
    end.

header_to_string(undefined)            -> $-;
header_to_string(N) when is_integer(N) -> integer_to_list(N);
header_to_string(A) when is_atom(A)    -> atom_to_list(A);
header_to_string(S) when is_list(S)    -> S.

header_to_string(_, undefined) ->
    $-;
header_to_string(Name, Header) ->
    RE = [Name, "\s?[^:]*:\s?(.*)\r\n"],
    case re:run(Header, RE, [caseless, {capture, all_but_first, list}]) of
        {match, [Value]} -> Value;
        _                -> $-
    end.

no_ctl([H|T]) when H < 32 ->
    no_ctl(T);
no_ctl([H|T]) ->
    [H|no_ctl(T)];
no_ctl([]) ->
    [].
