-module(yaws_syslogger_sup).

-behaviour(supervisor).

-include("yaws_syslogger.hrl").

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

