-module(yaws_customlog).


%% API
-export([
         parse/1
        ]).


%%====================================================================
%% Public API.
%%====================================================================
parse(String) ->
    parse(String, 0, []).

%%====================================================================
%% Internal functions
%%====================================================================
parse([], _, Tokens) ->
    lists:reverse(Tokens);


parse([$%,$%|Rest], Col, Tokens) ->
    parse(Rest, Col+2, [{char, $%}|Tokens]);
parse([$%|Rest], Col, Tokens) ->
    {Cond, Col1, Rest1} = parse_logcond(Rest, Col+1),
    case Rest1 of
        [$a|Rest2] -> parse(Rest2, Col1+1, [{remote_ip,        Cond}|Tokens]);
        [$B|Rest2] -> parse(Rest2, Col1+1, [{response_length,  Cond}|Tokens]);
        [$b|Rest2] -> parse(Rest2, Col1+1, [{response_length,  Cond}|Tokens]);
        [$D|Rest2] -> parse(Rest2, Col1+1, [{ms_time,          Cond}|Tokens]);
        [$H|Rest2] -> parse(Rest2, Col1+1, [{request_protocol, Cond}|Tokens]);
        [$h|Rest2] -> parse(Rest2, Col1+1, [{remote_host,      Cond}|Tokens]);
        [$l|Rest2] -> parse(Rest2, Col1+1, [{remote_name,      Cond}|Tokens]);
        [$m|Rest2] -> parse(Rest2, Col1+1, [{request_method,   Cond}|Tokens]);
        [$p|Rest2] -> parse(Rest2, Col1+1, [{pid,              Cond}|Tokens]);
        [$q|Rest2] -> parse(Rest2, Col1+1, [{query_string,     Cond}|Tokens]);
        [$r|Rest2] -> parse(Rest2, Col1+1, [{request,          Cond}|Tokens]);
        [$s|Rest2] -> parse(Rest2, Col1+1, [{status,           Cond}|Tokens]);
        [$t|Rest2] -> parse(Rest2, Col1+1, [{date,             Cond}|Tokens]);
        [$T|Rest2] -> parse(Rest2, Col1+1, [{time,             Cond}|Tokens]);
        [$u|Rest2] -> parse(Rest2, Col1+1, [{user,             Cond}|Tokens]);
        [$U|Rest2] -> parse(Rest2, Col1+1, [{url_path,         Cond}|Tokens]);
        [$v|Rest2] -> parse(Rest2, Col1+1, [{servername,       Cond}|Tokens]);
        [${|Rest2] ->
            {Token, Col2, Rest3} = parse_logvar(Rest2, Col1+1),
            parse(Rest3, Col2, [{Token, Cond}|Tokens]);
        [C|_] -> throw({error, Col1, "unknown log directive %" ++ [C]});
        []    -> throw({error, Col1, "premature end log format"})
    end;
parse([C|Rest], Col, Tokens) ->
    parse(Rest, Col+1, [{char, C}|Tokens]).



%%====================================================================
parse_logcond([$!|Rest], Col) ->
    case parse_logcond1(Rest, Col+1, []) of
        {[], Col1, Rest1}   -> {none,            Col1, Rest1};
        {Cond, Col1, Rest1} -> {{nomatch, Cond}, Col1, Rest1}
    end;
parse_logcond(Rest, Col) ->
    case parse_logcond1(Rest, Col+1, []) of
        {[], Col1, Rest1}   -> {none,          Col1, Rest1};
        {Cond, Col1, Rest1} -> {{match, Cond}, Col1, Rest1}
    end.


parse_logcond1([$1,$0,X|Rest], Col, Cond) when X >= $0, X =< $1 ->
    parse_logcond2(Rest, Col+3, [list_to_integer([$1,$0,X])|Cond]);
parse_logcond1([$2,$0,X|Rest], Col, Cond) when X >= $0, X =< $6 ->
    parse_logcond2(Rest, Col+3, [list_to_integer([$2,$0,X])|Cond]);
parse_logcond1([$3,$0,X|Rest], Col, Cond) when X >= $0, X =< $7 ->
    parse_logcond2(Rest, Col+3, [list_to_integer([$3,$0,X])|Cond]);
parse_logcond1([$4,$0,X|Rest], Col, Cond) when X >= $0, X =< $9 ->
    parse_logcond2(Rest, Col+3, [list_to_integer([$4,$0,X])|Cond]);
parse_logcond1([$4,$1,X|Rest], Col, Cond) when X >= $0, X =< $7 ->
    parse_logcond2(Rest, Col+3, [list_to_integer([$4,$1,X])|Cond]);
parse_logcond1([$5,$0,X|Rest], Col, Cond) when X >= $0, X =< $5 ->
    parse_logcond2(Rest, Col+3, [list_to_integer([$4,$1,X])|Cond]);
parse_logcond1(Rest, Col, Cond) ->
    {Cond, Col, Rest}.


parse_logcond2([$,|Rest], Col, Cond) ->
    parse_logcond1(Rest, Col+1, Cond);
parse_logcond2(Rest, Col, Cond) ->
    {Cond, Col, Rest}.



%%====================================================================
parse_logvar(Rest, Col) ->
    parse_logvar(Rest, Col, []).

parse_logvar([], Col, Var) ->
    throw({error, Col, "variable '" ++ lists:reverse(Var) ++ "' not terminated"});
parse_logvar([$},$C|Rest], Col, Var) ->
    {{cookie, lists:reverse(Var)}, Col+2, Rest};
parse_logvar([$},$i|Rest], Col, Var) ->
    {{request_header, string:to_lower(lists:reverse(Var))}, Col+2, Rest};
parse_logvar([$},$o|Rest], Col, Var) ->
    {{response_header, string:to_lower(lists:reverse(Var))}, Col+2, Rest};
parse_logvar([C|Rest], Col, Var) ->
    parse_logvar(Rest, Col+1, [C|Var]).



