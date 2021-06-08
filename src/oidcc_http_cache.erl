-module(oidcc_http_cache).

-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([stop/0]).
-export([cache_http_result/3]).
-export([lookup_http_call/2]).
-export([enqueue_http_call/2]).
-export([trigger_cleaning/0]).
%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-record(state, {ets_cache = undefined, last_clean = undefined}).

%% API.
-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec stop() -> ok.
stop() ->
    gen_server:cast(?MODULE, stop).

cache_http_result(Method, Request, Result) ->
    Key = {Method, Request},
    gen_server:call(?MODULE, {cache_http, Key, Result}).

lookup_http_call(Method, Request) ->
    Key = {Method, Request},
    read_cache(Key).

enqueue_http_call(Method, Request) ->
    Key = {Method, Request},
    gen_server:call(?MODULE, {enqueue, Key}, 30000).

trigger_cleaning() ->
    gen_server:cast(?MODULE, clean_cache).

-define(REQUEST_BUFFER, 30).

%% gen_server.
init(_) ->
    EtsCache = ets:new(oidcc_ets_http_cache, [set, protected, named_table]),
    Now = erlang:system_time(seconds),
    {ok, #state{ets_cache = EtsCache, last_clean = Now}}.

handle_call({enqueue, Key}, _From, State) ->
    CacheDuration = application:get_env(oidcc, http_cache_duration, none),
    Result = insert_into_cache(Key, pending, CacheDuration, State),
    {reply, Result, State};
handle_call({cache_http, Key, Result}, _From, State) ->
    CacheDuration = application:get_env(oidcc, http_cache_duration, none),
    ok = trigger_cleaning_if_needed(State),
    ok = insert_into_cache(Key, Result, CacheDuration, State),
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

insert_into_cache(Key, Result, Duration, #state{ets_cache = EtsCache})
    when is_integer(Duration), Duration > 0 ->
    Now = erlang:system_time(seconds),
    Timeout =
        case Result of
            pending ->
                Now + oidcc_http_util:request_timeout(s) + ?REQUEST_BUFFER;
            _ ->
                Now + Duration
        end,
    Inserted = ets:insert_new(EtsCache, {Key, Timeout, Result}),
    case {Result, Inserted} of
        {pending, true} ->
            true;
        {pending, false} ->
            false;
        {_, _} ->
            true = ets:insert(EtsCache, {Key, Timeout, Result}),
            ok
    end;
insert_into_cache(_Key, pending, _NoDuration, _State) ->
    %% if not using cache always perform the request
    true;
insert_into_cache(_Key, _Result, _NoDuration, _State) ->
    ok.

handle_cast(clean_cache, State) ->
    NewState = clean_cache(State),
    {noreply, NewState};
handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

read_cache(Key) ->
    Now = erlang:system_time(seconds),
    case ets:lookup(oidcc_ets_http_cache, Key) of
        [{Key, Timeout, Result}] ->
            return_if_not_outdated(Result, Timeout >= Now);
        [] ->
            {error, not_found}
    end.

trigger_cleaning_if_needed(#state{last_clean = LastClean}) ->
    Now = erlang:system_time(seconds),
    CleanTimeout = application:get_env(oidcc, http_cache_clean, 60),
    case Now - LastClean >= CleanTimeout of
        true ->
            trigger_cleaning(),
            ok;
        _ ->
            ok
    end.

clean_cache(#state{ets_cache = CT} = State) ->
    Now = erlang:system_time(seconds),
    ets:select_delete(CT, [{{'_', '$1', '_'}, [{'<', '$1', Now}], [true]}]),
    State#state{last_clean = Now}.

return_if_not_outdated(Result, true) ->
    {ok, Result};
return_if_not_outdated(_, _) ->
    trigger_cleaning(),
    {error, outdated}.
