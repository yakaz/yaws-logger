%% $Id$
-module(yaws_logger_sup).
-vsn('$Revision$ ').

-behaviour(supervisor).

-include("yaws_logger.hrl").

%% API
-export([
         start_link/0
        ]).

%% Supervisor callbacks
-export([init/1]).

%%====================================================================
%% API functions
%%====================================================================
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================
init([]) ->
    {ok, {{one_for_one, 0, 1}, []}}.

