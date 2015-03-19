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

-module(yaws_logger_netutils).


%% API
-export([
         parse_ip/1,
         match_ip/2
        ]).

-include_lib("kernel/include/inet.hrl").

-define(MASK_IPV4,    16#FFFFFFFF).
-define(MAXBITS_IPV4, 32).

-define(MASK_IPV6,    16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).
-define(MAXBITS_IPV6, 128).

%%====================================================================
%% Public API.
%%====================================================================
-spec parse_ip(string()) ->
    inet:ip_address() | {inet:ip_address(), inet:ip_address()}.

parse_ip(Str) ->
    case parse(Str) of
        {ipv4, Ip} ->
            integer_to_ip(ipv4, Ip);
        {ipv6, Ip} ->
            integer_to_ip(ipv6, Ip);
        {ipv4, Ip, Mask} ->
            Wildcard  = netmask_to_wildcard(ipv4, Mask),
            NetAddr   = (Ip band netmask_to_integer(ipv4, Mask)),
            Broadcast = NetAddr + Wildcard,
            IpMin     = NetAddr + 1,
            IpMax     = Broadcast - 1,
            {integer_to_ip(ipv4, IpMin), integer_to_ip(ipv4, IpMax)};
        {ipv6, Ip, Mask} ->
            Wildcard  = netmask_to_wildcard(ipv6, Mask),
            NetAddr   = (Ip band netmask_to_integer(ipv6, Mask)),
            IpMin = NetAddr,
            IpMax = NetAddr + Wildcard,
            {integer_to_ip(ipv6, IpMin), integer_to_ip(ipv6, IpMax)}
    end.


%% ----
-spec match_ip(inet:ip_address(),
               inet:ip_address() | {inet:ip_address(), inet:ip_address()}) ->
    boolean().

match_ip({A,B,C,D}, {A,B,C,D}) ->
    true;
match_ip({A,B,C,D,E,F,G,H}, {A,B,C,D,E,F,G,H}) ->
    true;
match_ip(Ip, {Ip1, Ip2}) ->
    case is_greater_ip(Ip, Ip1) of
        true  -> is_lower_ip(Ip, Ip2);
        false -> false
    end;
match_ip(_, _) ->
    false.

%%====================================================================
%% Internal functions
%%====================================================================
parse(Str) when is_list(Str) ->
    [Ip|Rest]   = string:tokens(Str, [$/]),
    {Type, Int} = ip_to_integer(Ip),
    case Rest of
        []  -> {Type, Int};
        [M] -> {Type, Int, list_to_integer(M)};
        _   -> throw({error, einval})
    end;
parse(_) ->
    throw({error, einval}).

%% ----
ip_to_integer(Ip) ->
    case inet_parse:ipv6_address(Ip) of
        {ok, {0,0,0,0,0,16#FFFF,N1,N2}} ->
            {ipv4, (N1 bsl 16) bor N2};
        {ok, {N1,N2,N3,N4,N5,N6,N7,N8}} ->
            {ipv6, (N1 bsl 112) bor (N2 bsl 96) bor (N3 bsl 80) bor (N4 bsl 64)
                 bor (N5 bsl 48) bor (N6 bsl 32) bor (N7 bsl 16) bor N8};
        {error, Reason} ->
            throw({error, Reason})
    end.

%% ----
integer_to_ip(ipv4, I) when is_integer(I), I =< ?MASK_IPV4 ->
    N1 =  I bsr 24,
    N2 = (I band ((1 bsl 24) - 1)) bsr 16,
    N3 = (I band ((1 bsl 16) - 1)) bsr 8,
    N4 = (I band ((1 bsl 8) - 1)),
    {N1, N2, N3, N4};
integer_to_ip(ipv6, I) when is_integer(I), I =< ?MASK_IPV6 ->
    N1 =  I bsr 112,
    N2 = (I band ((1 bsl 112) - 1)) bsr 96,
    N3 = (I band ((1 bsl  96) - 1)) bsr 80,
    N4 = (I band ((1 bsl  80) - 1)) bsr 64,
    N5 = (I band ((1 bsl  64) - 1)) bsr 48,
    N6 = (I band ((1 bsl  48) - 1)) bsr 32,
    N7 = (I band ((1 bsl  32) - 1)) bsr 16,
    N8 = (I band ((1 bsl  16) - 1)),
    {N1, N2, N3, N4, N5, N6, N7, N8};
integer_to_ip(_, _) ->
    throw({error, einval}).

%% ----
netmask_to_wildcard(ipv4, Mask) ->
    (1 bsl (?MAXBITS_IPV4 - Mask) - 1);
netmask_to_wildcard(ipv6, Mask) ->
    (1 bsl (?MAXBITS_IPV6 - Mask) - 1).

%% ----
netmask_to_integer(ipv4, Mask) ->
    ?MASK_IPV4 bsr (?MAXBITS_IPV4 - Mask) bsl (?MAXBITS_IPV4 - Mask);
netmask_to_integer(ipv6, Mask) ->
    ?MASK_IPV6 bsr (?MAXBITS_IPV6 - Mask) bsl (?MAXBITS_IPV6 - Mask).

%% ----
is_greater_ip({A,B,C,D1}, {A,B,C,D2}) when D1 < D2 ->
    false;
is_greater_ip({A,B,C1,_}, {A,B,C2,_}) when C1 < C2 ->
    false;
is_greater_ip({A,B1,_,_}, {A,B2,_,_}) when B1 < B2 ->
    false;
is_greater_ip({A1,_,_,_}, {A2,_,_,_}) when A1 < A2 ->
    false;
is_greater_ip({_,_,_,_}, {_,_,_,_}) ->
    true;
is_greater_ip({A,B,C,D,E,F,G,H1}, {A,B,C,D,E,F,G,H2}) when H1 < H2 ->
    false;
is_greater_ip({A,B,C,D,E,F,G1,_}, {A,B,C,D,E,F,G2,_}) when G1 < G2 ->
    false;
is_greater_ip({A,B,C,D,E,F1,_,_}, {A,B,C,D,E,F2,_,_}) when F1 < F2 ->
    false;
is_greater_ip({A,B,C,D,E1,_,_,_}, {A,B,C,D,E2,_,_,_}) when E1 < E2 ->
    false;
is_greater_ip({A,B,C,D1,_,_,_,_}, {A,B,C,D2,_,_,_,_}) when D1 < D2 ->
    false;
is_greater_ip({A,B,C1,_,_,_,_,_}, {A,B,C2,_,_,_,_,_}) when C1 < C2 ->
    false;
is_greater_ip({A,B1,_,_,_,_,_,_}, {A,B2,_,_,_,_,_,_}) when B1 < B2 ->
    false;
is_greater_ip({A1,_,_,_,_,_,_,_}, {A2,_,_,_,_,_,_,_}) when A1 < A2 ->
    false;
is_greater_ip({_,_,_,_,_,_,_,_}, {_,_,_,_,_,_,_,_}) ->
    true.

%% ----
is_lower_ip(Ip1, Ip2) ->
    is_greater_ip(Ip2, Ip1).
