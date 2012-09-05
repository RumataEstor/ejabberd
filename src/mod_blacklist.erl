%%%-------------------------------------------------------------------
%%% @author Dmitry Belyaev <be.dmitry@gmail.com>
%%% @copyright (C) 2012, Dmitry Belyaev
%%% @doc
%%%    Simple blacklisting hardcoded in config.
%%%    Configuration: Opts = [{BlockTo, [BlockFrom, ...]}, ...]
%%%                   where BlockTo and BlockFrom are bare jids as strings.
%%%    Sample config to block incoming stazas to u1 from both u2 and u3, and from u2 to u3:
%%%       {mod_blacklist, [{"u1@localhost", ["u2@localhost", "u3@localhost"]},
%%%                        {"u3@localhost", ["u2@localhost"]}]},
%%% @end
%%% Created :  5 Sep 2012 by Dmitry Belyaev <be.dmitry@gmail.com>
%%%-------------------------------------------------------------------
-module(mod_blacklist).

-behaviour(gen_server).
-behavior(gen_mod).

%% API
-export([start/2, stop/1, check_packet/6]).


%% supervisor start fun
-export([start_link/3]).

%% gen_server API
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).


-include("ejabberd.hrl").
-include("jlib.hrl").

-define(SERVER, ?MODULE).
-define(SUPERVISOR, ejabberd_sup).

-record(state, {host}).

%%%===================================================================
%%% API
%%%===================================================================
start_link(Proc, Host, Opts) ->
    gen_server:start_link({local, Proc}, ?MODULE, {Proc, Host, Opts}, []).


check_packet(_, _User, Server, _PrivacyList, {From, To, _}, in) ->
    Proc = gen_mod:get_module_proc(Server, ?MODULE),
    check_incoming_packet(Proc, From, To);
check_packet(_, _User, _Server, _PrivacyList, _FromToPacket, _Dir) ->
    allow.

%%====================================================================
%% gen_mod callbacks
%%====================================================================
start(Host, Opts) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    ChildSpec = {Proc, {?MODULE, start_link, [Proc, Host, Opts]},
                 permanent, 2000, worker, [?MODULE]},
    supervisor:start_child(?SUPERVISOR, ChildSpec).


stop(Host) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    gen_server:call(Proc, stop),
    supervisor:delete_child(?SUPERVISOR, Proc).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init({Proc, Host, Opts}) ->
    init_table(Proc, Opts),
    ejabberd_hooks:add(privacy_check_packet, Host,
                       ?MODULE, check_packet, 10),
    {ok, #state{host=Host}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, #state{host=Host}) ->
    ejabberd_hooks:delete(privacy_check_packet, Host,
                          ?MODULE, check_packet, 10),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
init_table(Proc, Opts) ->
    Proc = ets:new(Proc, [public, named_table, {read_concurrency, true}, bag]),
    Objects = lists:flatten([[{ToJid, FromJid} || FromJid <- Blacklisted] || {ToJid, Blacklisted} <- Opts]),
    true = ets:insert(Proc, Objects).


check_incoming_packet(Proc, From, To) ->
    FromString = jlib:jid_to_string(jlib:jid_remove_resource(From)),
    ToString = jlib:jid_to_string(jlib:jid_remove_resource(To)),
    case ets:match_object(Proc, {ToString, FromString}) of
        [] -> allow;
        _ -> {stop, deny}
    end.
