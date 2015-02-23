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

-module(lager_yaws_logger_proxy_backend).

-behaviour(gen_event).

%% gen_event callbacks
-export([init/1, handle_call/2, handle_event/2, handle_info/2, terminate/2,
         code_change/3]).


%% API
-export([config_to_id/1]).

-record(state, {type          :: access | auth | any,
                backend       :: atom(),
                backend_state :: any()}).


%% ===================================================================
%% API.
%% ===================================================================
config_to_id(Config) ->
    Backend = proplists:get_value(backend, Config, lager_console_backend),
    Config1 = lists:keydelete(backend, 1, lists:keydelete(type, 1, Config)),
    {_, Id} = Backend:config_to_id(Config1),
    {?MODULE, Id}.

%% ===================================================================
%% gen_server callbacks.
%% ===================================================================
init(Config) ->
    Backend = proplists:get_value(backend, Config, lager_console_backend),
    Type    = proplists:get_value(type, Config, any),
    Config1 = lists:keydelete(backend, 1, lists:keydelete(type, 1, Config)),

    {ok, BackendState} = Backend:init(Config1),
    {ok, #state{backend=Backend, type=Type, backend_state=BackendState}}.

%% ----
handle_call(Request, #state{backend=BckMod, backend_state=BckSt0}=State) ->
    {ok, Reply, BckSt1} = BckMod:handle_call(Request, BckSt0),
    {ok, Reply, State#state{backend_state=BckSt1}}.

%% ----
handle_event({log, Message},
             #state{type=Type, backend=BckMod, backend_state=BckSt0}=State) ->
    MD = lager_msg:metadata(Message),
    {ok, BckSt1} = case lists:keyfind(type, 1, MD) of
                       {type, T} when Type == any; T == Type ->
                           BckMod:handle_event({log, Message}, BckSt0);
                       _ ->
                           {ok, BckSt0}
                   end,
    {ok, State#state{backend_state=BckSt1}};
handle_event(Event, #state{backend=BckMod, backend_state=BckSt0}=State) ->
    {ok, BckSt1} = BckMod:handle_event(Event, BckSt0),
    {ok, State#state{backend_state=BckSt1}}.

%% ----
handle_info(Info, #state{backend=BckMod, backend_state=BckSt0}=State) ->
    {ok, BckSt1} = BckMod:handle_info(Info, BckSt0),
    {ok, State#state{backend_state=BckSt1}}.

%% ----
terminate(Reason, #state{backend=BckMod, backend_state=BckSt}) ->
    BckMod:terminate(Reason, BckSt).

%% ----
code_change(OldVsn, #state{backend=BckMod, backend_state=BckSt0}=State, Extra) ->
    {ok, BckSt1} = BckMod:code_change(OldVsn, BckSt0, Extra),
    {ok, State#state{backend_state=BckSt1}}.

%%====================================================================
%% Internal functions
%%====================================================================
