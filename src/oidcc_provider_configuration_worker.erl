%%%-------------------------------------------------------------------
%% @doc OIDC Config Provider Worker
%%
%% Loads and continuously refreshes the OIDC configuration and JWKs
%%
%% The worker supports reading values concurrently via an ets table. To use
%% this performance improvement, the worker has to be registered with a
%% `{local, Name}'. No name / `{global, Name}' and `{via, RegModule, ViaName}'
%% are not supported.
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_provider_configuration_worker).

-feature(maybe_expr, enable).

-behaviour(gen_server).

-include("oidcc_provider_configuration.hrl").

-include_lib("jose/include/jose_jwk.hrl").

-export([get_jwks/1]).
-export([get_provider_configuration/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_continue/2]).
-export([handle_info/2]).
-export([init/1]).
-export([refresh_configuration/1]).
-export([refresh_jwks/1]).
-export([refresh_jwks_for_unknown_kid/2]).
-export([start_link/1]).

-export_type([opts/0]).

%% Configuration Options
%%
%% <ul>
%%   <li>`name' - The gen_server name of the provider.</li>
%%   <li>`issuer' - The issuer URI.</li>
%%   <li>`provider_configuration_opts' - Options for the provider configuration fetching.</li>
%% </ul>
-type opts() :: #{
    name => gen_server:server_name(),
    issuer := uri_string:uri_string(),
    provider_configuration_opts => oidcc_provider_configuration:opts()
}.

-record(state, {
    provider_configuration = undefined :: #oidcc_provider_configuration{} | undefined,
    jwks = undefined :: jose_jwk:key() | undefined,
    issuer :: uri_string:uri_string(),
    provider_configuration_opts :: oidcc_provider_configuration:opts(),
    configuration_refresh_timer = undefined :: timer:tref() | undefined,
    jwks_refresh_timer = undefined :: timer:tref() | undefined,
    ets_table = undefined :: ets:table() | undefined
}).

%% @doc Start Configuration Provider
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>,
%%     name => {local, google_config_provider}
%%   }).
%% '''
%%
%% ```
%% %% ...
%%
%% -behaviour(supervisor).
%%
%% %% ...
%%
%% init(_opts) ->
%%   SupFlags = #{strategy => one_for_one, intensity => 1, period => 5},
%%   ChildSpecs = [#{id => google_config_provider,
%%     start => {oidcc_provider_configuration_worker,
%%               start_link,
%%               [
%%                 #{issuer => <<"https://accounts.google.com">>}
%%               ]},
%%     restart => permanent,
%%     type => worker,
%%     modules => [oidcc_provider_configuration_worker]}],
%%   {ok, {SupFlags, ChildSpecs}}.
%% '''
%% @end
%% @since 3.0.0
-spec start_link(Opts :: opts()) -> gen_server:start_ret().
start_link(Opts) ->
    case maps:get(name, Opts, undefined) of
        undefined ->
            gen_server:start_link(?MODULE, Opts, []);
        Name ->
            gen_server:start_link(Name, ?MODULE, Opts, [])
    end.

%% @private
init(Opts) ->
    EtsTable = register_ets_table(Opts),
    maybe
        {ok, Issuer} ?= get_issuer(Opts),
        ProviderConfigurationOpts = maps:get(provider_configuration_opts, Opts, #{}),
        {ok,
            #state{
                issuer = Issuer,
                provider_configuration_opts = ProviderConfigurationOpts,
                ets_table = EtsTable
            },
            {continue, load_configuration}}
    end.

%% @private
handle_call(
    get_provider_configuration, _From, #state{provider_configuration = Configuration} = State
) ->
    {reply, Configuration, State};
handle_call(get_jwks, _From, #state{jwks = Jwks} = State) ->
    {reply, Jwks, State}.

%% @private
handle_cast(refresh_configuration, State) ->
    {noreply, State, {continue, load_configuration}};
handle_cast(refresh_jwks, State) ->
    {noreply, State, {continue, load_jwks}};
handle_cast({refresh_jwks_for_unknown_kid, Kid}, #state{jwks = Jwks} = State) ->
    case has_kid(Jwks, Kid) of
        false ->
            {noreply, State, {continue, load_jwks}};
        true ->
            {noreply, State};
        unknown ->
            {noreply, State}
    end.

%% @private
handle_continue(
    load_configuration,
    #state{
        issuer = Issuer,
        provider_configuration_opts = ProviderConfigurationOpts,
        configuration_refresh_timer = OldTimer,
        ets_table = EtsTable
    } =
        State
) ->
    maybe_cancel_timer(OldTimer),

    maybe
        {ok, {Configuration, Expiry}} ?=
            oidcc_provider_configuration:load_configuration(
                Issuer,
                ProviderConfigurationOpts
            ),
        {ok, NewTimer} = timer:send_after(Expiry, configuration_expired),
        ok = store_in_ets(EtsTable, provider_configuration, Configuration),
        {noreply,
            State#state{
                provider_configuration = Configuration, configuration_refresh_timer = NewTimer
            },
            {continue, load_jwks}}
    else
        {error, Reason} ->
            {stop, {configuration_load_failed, Reason}, State}
    end;
handle_continue(
    load_jwks,
    #state{
        provider_configuration = Configuration,
        provider_configuration_opts = ProviderConfigurationOpts,
        jwks_refresh_timer = OldTimer,
        ets_table = EtsTable
    } =
        State
) ->
    #oidcc_provider_configuration{jwks_uri = JwksUri} = Configuration,

    maybe_cancel_timer(OldTimer),

    maybe
        {ok, {Jwks, Expiry}} ?=
            oidcc_provider_configuration:load_jwks(JwksUri, ProviderConfigurationOpts),
        {ok, NewTimer} = timer:send_after(Expiry, jwks_expired),
        ok = store_in_ets(EtsTable, jwks, Jwks),
        {noreply, State#state{jwks = Jwks, jwks_refresh_timer = NewTimer}}
    else
        {error, Reason} ->
            {stop, {jwks_load_failed, Reason}, State}
    end.

%% @private
handle_info(configuration_expired, State) ->
    {noreply, State#state{configuration_refresh_timer = undefined, jwks_refresh_timer = undefined},
        {continue, load_configuration}};
handle_info(jwks_expired, State) ->
    {noreply, State#state{jwks_refresh_timer = undefined}, {continue, load_jwks}}.

%% @doc Get Configuration
-spec get_provider_configuration(Name :: gen_server:server_ref()) ->
    oidcc_provider_configuration:t().
get_provider_configuration(Name) ->
    lookup_in_ets_or_call(Name, provider_configuration, get_provider_configuration).

%% @doc Get Parsed Jwks
-spec get_jwks(Name :: gen_server:server_ref()) -> jose_jwk:key().
get_jwks(Name) ->
    lookup_in_ets_or_call(Name, jwks, get_jwks).

%% @doc Refresh Configuration
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>
%%   }).
%%
%% %% Later
%%
%% oidcc_provider_configuration_worker:refresh_configuration(Pid).
%% '''
%% @end
%% @since 3.0.0
-spec refresh_configuration(Name :: gen_server:server_ref()) -> ok.
refresh_configuration(Name) ->
    refresh_configuration(Name, true).

-spec refresh_configuration(Name :: gen_server:server_ref(), Synchronous :: boolean()) -> ok.
refresh_configuration(Name, false) ->
    gen_server:cast(Name, refresh_configuration);
refresh_configuration(Name, true) ->
    refresh_configuration(Name, false),
    gen_server:call(Name, get_provider_configuration),
    ok.

%% @doc Refresh JWKs
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>
%%   }).
%%
%% %% Later
%%
%% oidcc_provider_configuration_worker:refresh_jwks(Pid).
%% '''
%% @end
%% @since 3.0.0
-spec refresh_jwks(Name :: gen_server:server_ref()) -> ok.
refresh_jwks(Name) -> refresh_jwks(Name, true).

-spec refresh_jwks(Name :: gen_server:server_ref(), Synchronous :: boolean()) -> ok.
refresh_jwks(Name, false) ->
    gen_server:cast(Name, refresh_jwks);
refresh_jwks(Name, true) ->
    refresh_jwks(Name, false),
    gen_server:call(Name, get_jwks),
    ok.

%% @doc Refresh JWKs if the provided `Kid' is not matching any currently loaded keys
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, Pid} =
%%   oidcc_provider_configuration_worker:start_link(#{
%%     issuer => <<"https://accounts.google.com">>
%%   }).
%%
%% oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(Pid, <<"kid">>).
%% '''
%% @end
%% @since 3.0.0
-spec refresh_jwks_for_unknown_kid(Name :: gen_server:server_ref(), Kid :: binary()) ->
    ok.
refresh_jwks_for_unknown_kid(Name, Kid) ->
    refresh_jwks_for_unknown_kid(Name, Kid, true).

-spec refresh_jwks_for_unknown_kid(
    Name :: gen_server:server_ref(), Kid :: binary(), Synchronous :: boolean()
) ->
    ok.
refresh_jwks_for_unknown_kid(Name, Kid, false) ->
    gen_server:cast(Name, {refresh_jwks_for_unknown_kid, Kid});
refresh_jwks_for_unknown_kid(Name, Kid, true) ->
    refresh_jwks_for_unknown_kid(Name, Kid, false),
    gen_server:call(Name, get_jwks),
    ok.

-spec get_issuer(Opts :: opts()) -> {ok, binary()} | {error, issuer_required}.
get_issuer(Opts) ->
    case maps:get(issuer, Opts, undefined) of
        undefined ->
            {error, issuer_required};
        Issuer when erlang:is_binary(Issuer) ->
            {ok, Issuer}
    end.

%% Checking of existing kid values is a bit wonky because of partial support
%% in jose. see: https://github.com/potatosalad/erlang-jose/issues/28
-spec has_kid(Jwk :: jose_jwk:key(), Kid :: binary()) -> boolean() | unknown.
has_kid(#jose_jwk{fields = #{<<"kid">> := Kid}}, Kid) ->
    true;
has_kid(#jose_jwk{fields = #{<<"kid">> := _}}, _Kid) ->
    false;
has_kid(#jose_jwk{keys = {jose_jwk_set, Keys}}, Kid) ->
    lists:foldl(
        fun
            (_Key, Acc) when is_boolean(Acc) ->
                Acc;
            (Key, unknown) ->
                has_kid(Key, Kid)
        end,
        unknown,
        Keys
    ).

-spec maybe_cancel_timer(Timer :: undefined | timer:tref()) -> ok.
maybe_cancel_timer(undefined) ->
    ok;
maybe_cancel_timer(TRef) ->
    {ok, cancel} = timer:cancel(TRef).

-spec store_in_ets(Table :: ets:table() | undefined, Key :: atom(), Value :: term()) -> ok.
store_in_ets(undefined, _Key, _Value) ->
    ok;
store_in_ets(Table, Key, Value) ->
    true = ets:insert(Table, [{Key, Value}]),
    ok.

-spec lookup_in_ets_or_call(Name :: gen_server:server_ref(), Key :: atom(), Call :: term()) ->
    term().
lookup_in_ets_or_call(Name, Key, Call) ->
    maybe
        {ok, TableName} ?= get_ets_table_name(Name),
        [{Key, Value}] ?= ets:lookup(TableName, Key),
        Value
    else
        %% Fall Back to synchronous gen_server lookup if ets table can't be
        %% located or the value is not present yet
        _ -> gen_server:call(Name, Call)
    end.

-spec get_ets_table_name(WorkerRef :: gen_server:server_ref()) ->
    {ok, gen_server:server_ref()} | error.
get_ets_table_name(WorkerName) when is_atom(WorkerName) ->
    {ok, erlang:list_to_atom(erlang:atom_to_list(WorkerName) ++ "_table")};
get_ets_table_name(_Ref) ->
    error.

-spec register_ets_table(Opts :: opts()) -> ets:table() | undefined.
register_ets_table(Opts) ->
    case maps:get(name, Opts, undefined) of
        {local, WorkerName} ->
            Name = erlang:list_to_atom(erlang:atom_to_list(WorkerName) ++ "_table"),
            ets:new(Name, [named_table, bag, protected, {read_concurrency, true}]);
        _OtherName ->
            undefined
    end.
