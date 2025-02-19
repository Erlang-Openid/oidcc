%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_token_introspection).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("""
OAuth Token Introspection.

See https://datatracker.ietf.org/doc/html/rfc7662.

## Records

To use the records, import the definition:

```erlang
-include_lib(["oidcc/include/oidcc_token_introspection.hrl"]).
```

## Telemetry

See [`Oidcc.TokenIntrospection`](`m:'Elixir.Oidcc.TokenIntrospection'`).
""").
?MODULEDOC(#{since => <<"3.0.0">>}).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").
-include("oidcc_token.hrl").
-include("oidcc_token_introspection.hrl").

-export([introspect/3]).

-export_type([error/0]).
-export_type([opts/0]).
-export_type([t/0]).

?DOC("""
Introspection Result.

See https://datatracker.ietf.org/doc/html/rfc7662#section-2.2.
""").
?DOC(#{since => <<"3.0.0">>}).
-type t() :: #oidcc_token_introspection{
    active :: boolean(),
    client_id :: binary(),
    exp :: pos_integer(),
    scope :: oidcc_scope:scopes(),
    username :: binary(),
    iss :: binary()
}.

?DOC(#{since => <<"3.0.0">>}).
-type opts() :: #{
    preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
    request_opts => oidcc_http_util:request_opts(),
    dpop_nonce => binary(),
    client_self_only => boolean()
}.

?DOC(#{since => <<"3.0.0">>}).
-type error() :: client_id_mismatch | introspection_not_supported | oidcc_http_util:error().

-telemetry_event(#{
    event => [oidcc, load_configuration, start],
    description => <<"Emitted at the start of introspecting the token">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, stop],
    description => <<"Emitted at the end of introspecting the token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, exception],
    description => <<"Emitted at the end of introspecting the token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

?DOC("""
Introspect the given access token.

For a high level interface using `m:oidcc_provider_configuration_worker`
see `oidcc:introspect_token/5`.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

%% Get AccessToken

{ok, #oidcc_token_introspection{active = True}} =
  oidcc_token_introspection:introspect(AccessToken, ClientContext, #{}).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec introspect(Token, ClientContext, Opts) ->
    {ok, t()}
    | {error, error()}
when
    Token :: oidcc_token:t() | binary(),
    ClientContext :: oidcc_client_context:authenticated_t(),
    Opts :: opts().
introspect(
    #oidcc_token{access = #oidcc_token_access{token = AccessToken}},
    ClientContext,
    Opts
) ->
    introspect(AccessToken, ClientContext, Opts);
introspect(AccessToken, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId,
        client_secret = ClientSecret
    } = ClientContext,
    #oidcc_provider_configuration{
        introspection_endpoint = Endpoint0,
        issuer = Issuer,
        introspection_endpoint_auth_methods_supported = SupportedAuthMethods,
        introspection_endpoint_auth_signing_alg_values_supported = AllowAlgorithms
    } = Configuration,

    case Endpoint0 of
        undefined ->
            {error, introspection_not_supported};
        _ ->
            Header0 = [{"accept", "application/json"}],
            Body0 = [{<<"token">>, AccessToken}],

            RequestOpts = maps:get(request_opts, Opts, #{}),
            TelemetryOpts = #{
                topic => [oidcc, introspect_token],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },
            DpopOpts =
                case Opts of
                    #{dpop_nonce := DpopNonce} ->
                        #{nonce => DpopNonce};
                    _ ->
                        #{}
                end,
            maybe
                {ok, {Body, Header1}, AuthMethod} ?=
                    oidcc_auth_util:add_client_authentication(
                        Body0, Header0, SupportedAuthMethods, AllowAlgorithms, Opts, ClientContext
                    ),
                Endpoint = oidcc_auth_util:maybe_mtls_endpoint(
                    Endpoint0,
                    AuthMethod,
                    <<"introspection_endpoint">>,
                    ClientContext
                ),
                Header = oidcc_auth_util:add_dpop_proof_header(
                    Header1, post, Endpoint, DpopOpts, ClientContext
                ),
                Request =
                    {Endpoint, Header, "application/x-www-form-urlencoded",
                        uri_string:compose_query(Body)},
                {ok, {{json, Token}, _Headers}} ?=
                    oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
                {ok, TokenMap} ?= extract_response(Token),
                client_match(TokenMap, ClientContext, maps:get(client_self_only, Opts, true))
            else
                {error, {use_dpop_nonce, NewDpopNonce, _}} when
                    DpopOpts =:= #{}
                ->
                    %% only retry automatically if we didn't use a nonce the first time
                    %% (to avoid infinite loops)
                    introspect(
                        AccessToken,
                        ClientContext,
                        Opts#{dpop_nonce => NewDpopNonce}
                    );
                {error, Reason} ->
                    {error, Reason}
            end
    end.

-spec client_match(Introspection, ClientContext, ClientSelfOnly) ->
    {ok, t()} | {error, error()}
when
    Introspection :: t(),
    ClientContext :: oidcc_client_context:t(),
    ClientSelfOnly :: boolean().
client_match(Introspection, _, false) ->
    {ok, Introspection};
client_match(
    #oidcc_token_introspection{client_id = ClientId} = Introspection,
    #oidcc_client_context{client_id = ClientId},
    true
) ->
    {ok, Introspection};
client_match(_Introspection, _ClientContext, true) ->
    {error, client_id_mismatch}.

-spec extract_response(TokenMap) ->
    {ok, t()}
when
    TokenMap :: map().
extract_response(TokenMap) ->
    Active =
        case maps:get(<<"active">>, TokenMap, undefined) of
            true ->
                true;
            _ ->
                false
        end,
    Scope = maps:get(<<"scope">>, TokenMap, <<"">>),
    Username = maps:get(<<"username">>, TokenMap, undefined),
    TokenType = maps:get(<<"token_type">>, TokenMap, undefined),
    Exp = maps:get(<<"exp">>, TokenMap, undefined),
    Iat = maps:get(<<"iat">>, TokenMap, undefined),
    Nbf = maps:get(<<"nbf">>, TokenMap, undefined),
    Sub = maps:get(<<"sub">>, TokenMap, undefined),
    Aud = maps:get(<<"aud">>, TokenMap, undefined),
    Iss = maps:get(<<"iss">>, TokenMap, undefined),
    Jti = maps:get(<<"jti">>, TokenMap, undefined),
    ClientId = maps:get(<<"client_id">>, TokenMap, undefined),
    {ok, #oidcc_token_introspection{
        active = Active,
        scope = oidcc_scope:parse(Scope),
        client_id = ClientId,
        username = Username,
        exp = Exp,
        token_type = TokenType,
        iat = Iat,
        nbf = Nbf,
        sub = Sub,
        aud = Aud,
        iss = Iss,
        jti = Jti,
        extra = maps:without(
            [
                <<"scope">>,
                <<"active">>,
                <<"username">>,
                <<"exp">>,
                <<"client_id">>,
                <<"token_type">>,
                <<"iat">>,
                <<"nbf">>,
                <<"sub">>,
                <<"aud">>,
                <<"iss">>,
                <<"jti">>
            ],
            TokenMap
        )
    }}.
