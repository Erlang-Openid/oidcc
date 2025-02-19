%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("""
OpenID Connect High Level Interface

## Setup

```erlang
{ok, Pid} =
  oidcc_provider_configuration_worker:start_link(#{
    issuer => <<"https://accounts.google.com">>,
    name => {local, google_config_provider}
  }).
```

(or via a `m:supervisor`)

See `m:oidcc_provider_configuration_worker` for details

## Global Configuration

* `max_clock_skew` (default `0`) - Maximum allowed clock skew for JWT
  `exp` / `nbf` validation, in seconds
""").
?MODULEDOC(#{since => <<"3.0.0">>}).

-export([client_credentials_token/4]).
-export([create_redirect_url/4]).
-export([initiate_logout_url/4]).
-export([introspect_token/5]).
-export([jwt_profile_token/6]).
-export([refresh_token/5]).
-export([retrieve_token/5]).
-export([retrieve_userinfo/5]).

?DOC("""
Create Auth Redirect URL

## Examples

```erlang
{ok, RedirectUri} =
      oidcc:create_redirect_url(
    provider_name,
    <<"client_id">>,
    <<"client_secret">>
    #{redirect_uri: <<"https://my.server/return"}
  ),

%% RedirectUri = https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec create_redirect_url(
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ok, Uri} | {error, oidcc_client_context:error() | oidcc_authorization:error()}
when
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary() | unauthenticated,
    Opts :: oidcc_authorization:opts() | oidcc_client_context:opts(),
    Uri :: uri_string:uri_string().
create_redirect_url(ProviderConfigurationWorkerName, ClientId, ClientSecret, Opts) ->
    {ClientContextOpts, OtherOpts0} = extract_client_context_opts(Opts),
    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        {ok, ClientContext, OtherOpts} = oidcc_profile:apply_profiles(ClientContext0, OtherOpts0),
        oidcc_authorization:create_redirect_url(ClientContext, OtherOpts)
    end.

?DOC("""
Retrieve the token using the authcode received before and directly validate
the result.

The authcode was sent to the local endpoint by the OpenId Connect provider,
using redirects.

## Examples

```erlang
%% Get AuthCode from Redirect

{ok, #oidcc_token{}} =
  oidcc:retrieve_token(
    AuthCode,
    provider_name,
    <<"client_id">>,
    <<"client_secret">>,
    #{redirect_uri => <<"https://example.com/callback">>}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec retrieve_token(
    AuthCode,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret | unauthenticated,
    Opts
) ->
    {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()}
when
    AuthCode :: binary(),
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: oidcc_token:retrieve_opts() | oidcc_client_context:opts().
retrieve_token(
    AuthCode,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh0 = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        {ok, ClientContext, OptsWithRefresh} = oidcc_profile:apply_profiles(
            ClientContext0, OptsWithRefresh0
        ),
        oidcc_token:retrieve(AuthCode, ClientContext, OptsWithRefresh)
    end.

?DOC("""
Load userinfo for the given token.

## Examples

```erlang
%% Get Token

{ok, #{<<"sub">> => Sub}} =
  oidcc:retrieve_userinfo(
    Token,
    provider_name,
    <<"client_id">>,
    <<"client_secret">>,
    #{}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec retrieve_userinfo
    (
        Token,
        ProviderConfigurationWorkerName,
        ClientId,
        ClientSecret | unauthenticated,
        Opts
    ) ->
        {ok, map()} | {error, oidcc_client_context:error() | oidcc_userinfo:error()}
    when
        Token :: oidcc_token:t(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary() | unauthenticated,
        Opts :: oidcc_userinfo:retrieve_opts_no_sub() | oidcc_client_context:opts();
    (Token, ProviderConfigurationWorkerName, ClientId, ClientSecret, Opts) ->
        {ok, map()} | {error, any()}
    when
        Token :: binary(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: oidcc_userinfo:retrieve_opts().
retrieve_userinfo(
    Token,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts0} = extract_client_context_opts(Opts),

    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        {ok, ClientContext, OtherOpts} = oidcc_profile:apply_profiles(ClientContext0, OtherOpts0),
        oidcc_userinfo:retrieve(Token, ClientContext, OtherOpts)
    end.

?DOC("""
Refresh Token.

## Examples

```erlang
%% Get Token and wait for its expiry

{ok, #oidcc_token{}} =
  oidcc:refresh_token(
    Token,
    provider_name,
    <<"client_id">>,
    <<"client_secret">>,
    #{expected_subject => <<"sub_from_initial_id_token">>}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec refresh_token
    (
        RefreshToken,
        ProviderConfigurationWorkerName,
        ClientId,
        ClientSecret | unauthenticated,
        Opts
    ) ->
        {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()}
    when
        RefreshToken :: binary(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: oidcc_token:refresh_opts() | oidcc_client_context:opts();
    (
        Token,
        ProviderConfigurationWorkerName,
        ClientId,
        ClientSecret,
        Opts
    ) ->
        {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()}
    when
        Token :: oidcc_token:t(),
        ProviderConfigurationWorkerName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: oidcc_token:refresh_opts_no_sub().
refresh_token(
    RefreshToken,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh0 = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        {ok, ClientContext, OptsWithRefresh} = oidcc_profile:apply_profiles(
            ClientContext0, OptsWithRefresh0
        ),
        oidcc_token:refresh(RefreshToken, ClientContext, OptsWithRefresh)
    end.

?DOC("""
Introspect the given access token.

## Examples

```erlang
%% Get AccessToken

{ok, #oidcc_token_introspection{active = True}} =
  oidcc:introspect_token(
    AccessToken,
    provider_name,
    <<"client_id">>,
    <<"client_secret">>,
    #{}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec introspect_token(
    Token,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ok, oidcc_token_introspection:t()}
    | {error, oidcc_client_context:error() | oidcc_token_introspection:error()}
when
    Token :: oidcc_token:t() | binary(),
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: oidcc_token_introspection:opts() | oidcc_client_context:opts().
introspect_token(
    Token,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) ->
    {ClientContextOpts, OtherOpts0} = extract_client_context_opts(Opts),

    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        {ok, ClientContext, OtherOpts} = oidcc_profile:apply_profiles(ClientContext0, OtherOpts0),
        oidcc_token_introspection:introspect(Token, ClientContext, OtherOpts)
    end.

?DOC("""
Retrieve JSON Web Token (JWT) Profile Token.

See https://datatracker.ietf.org/doc/html/rfc7523#section-4.

## Examples

```erlang
{ok, KeyJson} = file:read_file("jwt-profile.json"),
KeyMap = jose:decode(KeyJson),
Key = jose_jwk:from_pem(maps:get(<<"key">>, KeyMap)),

{ok, #oidcc_token{}} =
  oidcc_token:jwt_profile(
    <<"subject">>,
    provider_name,
    <<"client_id">>,
    <<"client_secret">>,
    Key,
    #{
     scope => [<<"scope">>],
     kid => maps:get(<<"keyId">>, KeyMap)
    }
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec jwt_profile_token(
    Subject,
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret | unauthenticated,
    Jwk,
    Opts
) -> {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()} when
    Subject :: binary(),
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Jwk :: jose_jwk:key(),
    Opts :: oidcc_token:jwt_profile_opts() | oidcc_client_context:opts().
jwt_profile_token(Subject, ProviderConfigurationWorkerName, ClientId, ClientSecret, Jwk, Opts) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh0 = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        {ok, ClientContext, OptsWithRefresh} = oidcc_profile:apply_profiles(
            ClientContext0, OptsWithRefresh0
        ),
        oidcc_token:jwt_profile(Subject, ClientContext, Jwk, OptsWithRefresh)
    end.

?DOC("""
Retrieve Client Credential Token.

See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4.

## Examples

```erlang
{ok, #oidcc_token{}} =
  oidcc:client_credentials_token(
    provider_name,
    <<"client_id">>,
    <<"client_secret">>,
    #{scope => [<<"scope">>]}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec client_credentials_token(
    ProviderConfigurationWorkerName,
    ClientId,
    ClientSecret,
    Opts
) -> {ok, oidcc_token:t()} | {error, oidcc_client_context:error() | oidcc_token:error()} when
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    ClientSecret :: binary(),
    Opts :: oidcc_token:client_credentials_opts() | oidcc_client_context:opts().
client_credentials_token(ProviderConfigurationWorkerName, ClientId, ClientSecret, Opts) ->
    {ClientContextOpts, OtherOpts} = extract_client_context_opts(Opts),

    RefreshJwksFun = oidcc_jwt_util:refresh_jwks_fun(ProviderConfigurationWorkerName),
    OptsWithRefresh0 = maps_put_new(refresh_jwks, RefreshJwksFun, OtherOpts),

    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                ClientSecret,
                ClientContextOpts
            ),
        {ok, ClientContext, OptsWithRefresh} = oidcc_profile:apply_profiles(
            ClientContext0, OptsWithRefresh0
        ),
        oidcc_token:client_credentials(ClientContext, OptsWithRefresh)
    end.

?DOC("""
Create Initiate URI for Relaying Party initiated Logout.

See https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout.

## Examples

```erlang
%% Get `Token` from `oidcc_token`

{ok, RedirectUri} =
  oidcc:initiate_logout_url(
    Token,
    provider_name,
    <<"client_id">>,
    #{post_logout_redirect_uri: <<"https://my.server/return"}}
  ).

%% RedirectUri = https://my.provider/logout?id_token_hint=IDToken&client_id=ClientId&post_logout_redirect_uri=https%3A%2F%2Fmy.server%2Freturn
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec initiate_logout_url(
    Token,
    ProviderConfigurationWorkerName,
    ClientId,
    Opts
) ->
    {ok, uri_string:uri_string()} | {error, oidcc_client_context:error() | oidcc_logout:error()}
when
    Token :: IdToken | oidcc_token:t() | undefined,
    IdToken :: binary(),
    ProviderConfigurationWorkerName :: gen_server:server_ref(),
    ClientId :: binary(),
    Opts :: oidcc_logout:initiate_url_opts() | oidcc_client_context:unauthenticated_opts().
initiate_logout_url(Token, ProviderConfigurationWorkerName, ClientId, Opts) ->
    {ClientContextOpts, OtherOpts0} = extract_client_context_opts(Opts),

    maybe
        {ok, ClientContext0} ?=
            oidcc_client_context:from_configuration_worker(
                ProviderConfigurationWorkerName,
                ClientId,
                unauthenticated,
                ClientContextOpts
            ),
        {ok, ClientContext, OtherOpts} = oidcc_profile:apply_profiles(ClientContext0, OtherOpts0),
        oidcc_logout:initiate_url(Token, ClientContext, OtherOpts)
    end.

-spec maps_put_new(Key, Value, Map1) -> Map2 when
    Key :: term(), Value :: term(), Map1 :: map(), Map2 :: map().
maps_put_new(Key, Value, Map) ->
    case maps:is_key(Key, Map) of
        true -> Map;
        false -> maps:put(Key, Value, Map)
    end.

-spec extract_client_context_opts(Opts) -> {ClientContextOpts, RestOpts} when
    Opts :: RestOpts | ClientContextOpts,
    RestOpts :: map(),
    ClientContextOpts :: oidcc_client_context:opts().
extract_client_context_opts(Opts) ->
    {
        maps:with([client_jwks], Opts),
        maps:without([client_jwks], Opts)
    }.
