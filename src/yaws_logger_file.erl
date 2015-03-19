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

-module(yaws_logger_file).

-behaviour(yaws_extended_logger).
-behaviour(gen_server).

-include_lib("kernel/include/file.hrl").
-include("yaws_logger.hrl").

%% API
-export([start_link/1]).

%% yaws_extended_logger callbacks
-export([open_log/5, close_log/1, write/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {name :: atom(),
                pid  :: pid()}).

-record(logstate, {name         :: string(),
                   fd           :: file:io_device(),
                   inode        :: integer(),
                   options      :: list(),
                   size         :: pos_integer() | infinity,
                   rotate       :: non_neg_integer(),
                   sync         :: boolean(),
                   rotate_timer :: reference()}).

-define(CHECK_INTERVAL, (10000 + random:uniform(10000))).
-define(REOPEN_INTERVAL, 5000).

%% ===================================================================
%% API
%% ===================================================================
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).


%% ===================================================================
%% yaws_extended_logger callbacks.
%% ===================================================================
open_log(Id, ServerName, Type, Dir, Opts) ->
    ensure_started(),
    Name   = file_name(ServerName, Type, Opts),
    Size   = file_size(ServerName, Type, Opts),
    Rotate = file_rotate(ServerName, Type, Opts),
    Sync   = file_sync(ServerName, Type, Opts),

    check_logfile_uniqueness(Id, Name, Dir),
    case yaws_logger_sup:start_child({Id, Name},
                                     [Name, Dir, Size, Rotate, Sync]) of
        {ok, Pid} -> #state{name=Id, pid=Pid};
        Else      -> throw(Else)
    end.

%% ----
close_log(State) ->
    gen_server:cast(State#state.pid, close).

%% ----
write(Msg, State) ->
    gen_server:cast(State#state.pid, {write, Msg}).


%% ===================================================================
%% gen_server callbacks.
%% ===================================================================
init([Name, Dir, Size, Rotate, Sync]) ->
    Filename = filename:join(Dir, Name),
    case filelib:ensure_dir(Filename) of
        ok ->
            Options = if
                          Sync == true -> [append, raw];
                          true         -> [append, raw, delayed_write]
                      end,
            case open(Filename, Options) of
                {ok, Fd, Inode} ->
                    TRef = erlang:send_after(?CHECK_INTERVAL, self(), check),
                    {ok, #logstate{name         = Filename,
                                   fd           = Fd,
                                   inode        = Inode,
                                   options      = Options,
                                   size         = Size,
                                   rotate       = Rotate,
                                   sync         = Sync,
                                   rotate_timer = TRef}};
                {error, Reason} ->
                    ?ERROR("Failed to open log file ~p: ~s",
                           [Filename, file:format_error(Reason)]),
                    {stop, Reason}
            end;
        {error, Reason} ->
            ?ERROR("Failed to open log file ~p: ~s",
                   [Filename, file:format_error(Reason)]),
            {stop, Reason}
    end.

%% ----
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% ----
handle_cast(_, #logstate{fd=undefined}=State) ->
    {noreply, State};
handle_cast({write,Msg}, State) ->
    file:write(State#logstate.fd, [unicode:characters_to_binary(Msg), $\n]),
    {noreply, State};
handle_cast(close, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

%% ----
handle_info(reopen, #logstate{fd=undefined}=State) ->
    {noreply, reopen_logfile(State)};
handle_info(_, #logstate{fd=undefined}=State) ->
    {noreply, State};
handle_info(check, State) ->
    TRef = erlang:send_after(?CHECK_INTERVAL, self(), check),
    {noreply, check_logfile(State#logstate{rotate_timer=TRef})};
handle_info(_Info, State) ->
    {noreply, State}.

%% ----
terminate(_Reason, State) ->
    case State#logstate.fd of
        undefined ->
            ok;
        Fd ->
            file:datasync(Fd),
            file:close(Fd)
    end.

%% ----
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%====================================================================
%% Internal functions
%%====================================================================
ensure_started() ->
    ok.

%% ---
file_name(_ServerName, Type, Opts) ->
    case lists:keyfind(file, 1, Opts) of
        {file, N} -> N;
        false     -> atom_to_list(Type) ++ ".log"
    end.

%% ---
file_size(_ServerName, _Type, Opts) ->
    case lists:keyfind(size, 1, Opts) of
        {size, Sz} -> Sz;
        false      -> infinity
    end.

%% ---
file_rotate(_ServerName, _Type, Opts) ->
    case lists:keyfind(rotate, 1, Opts) of
        {rotate, N} -> N;
        false       -> 5
    end.

%% ---
file_sync(_ServerName, _Type, Opts) ->
    case lists:keyfind(sync, 1, Opts) of
        {sync, B} -> B;
        false     -> false
    end.

%% ----
check_logfile_uniqueness(Id, Name, Dir) ->
    FileLoggers = supervisor:which_children(yaws_logger_sup),
    case [I || {{I,N},_,_,_} <- FileLoggers, N == Name, I /= Id] of
        [] ->
            ok;
        Others ->
            Filename = filename:join(Dir, Name),
            ?WARN("File ~p was already opened by loggers ~p.~n"
                  "This could lead to undefined behaviours.~n",
                  [Filename, Others])
    end.

%% ----
reopen_logfile(State) ->
    case State#logstate.fd of
        undefined ->
            State;
        Fd ->
            file:datasync(Fd),
            file:close(Fd)
    end,
    case open(State#logstate.name, State#logstate.options) of
        {ok, NewFd, Inode} ->
            ?INFO("File ~p was re-opened successfully~n",[State#logstate.name]),
            State#logstate{fd=NewFd, inode=Inode};
        {error, Reason} ->
            ?ERROR("Failed to re-open log file ~p: ~s~n",
                   [State#state.name, file:format_error(Reason)]),
            erlang:send_after(?REOPEN_INTERVAL, self(), reopen),
            State
    end.

%% ----
check_logfile(#logstate{name=Filename, fd=Fd, rotate=Count}=State) ->
    case file:read_file_info(Filename) of
        {ok, FI} when FI#file_info.inode /= State#logstate.inode ->
            check_logfile(reopen_logfile(State));

        {ok, FI} when FI#file_info.size > State#logstate.size ->
            case rotate(Fd, Filename, Count, State#logstate.options) of
                {ok, NewFd} ->
                    State#logstate{fd=NewFd};
                {ok, NewFd, Inode} ->
                    State#logstate{fd=NewFd, inode=Inode};
                {error, Reason} ->
                    ?ERROR("Failed to rotate log file ~p: ~s~n",
                           [State#logstate.name, file:format_error(Reason)]),
                    reopen_logfile(State)
            end;

        {ok, _} ->
            State;

        {error, Reason} ->
            ?ERROR("Failed to rotate log file ~p: ~s~n",
                   [State#logstate.name, file:format_error(Reason)]),
            reopen_logfile(State)
    end.

%% ----
open(Filename, Options)  ->
    case file:open(Filename, Options) of
        {ok, Fd} ->
            case file:read_file_info(Filename) of
                {ok, FI}        -> {ok, Fd, FI#file_info.inode};
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% ----
rotate(Fd, _, 0, _) ->
    case file:position(Fd, bof) of
        {ok, _} ->
            case file:truncate(Fd) of
                ok              -> {ok, Fd};
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
rotate(Fd, Filename, 1, Options) ->
    file:datasync(Fd),
    file:close(Fd),
    case file:rename(Filename, Filename++".0") of
        ok              -> open(Filename, Options);
        {error, Reason} -> {error, Reason}
    end;
rotate(Fd, Filename, C, Options) ->
    From = Filename ++ "." ++ integer_to_list(C - 2),
    To   = Filename ++ "." ++ integer_to_list(C - 1),
    file:rename(From, To),
    rotate(Fd, Filename, C-1, Options).
