%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_client_context).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("""
Client Configuration for authorization, token exchange, and userinfo.

For most projects, it makes sense to use `m:oidcc_provider_configuration_worker` and the high-level
interface of `oidcc`. In that case, direct usage of this module is not needed.

To use the record, import the definition:

```erlang
-include_lib(["oidcc/include/oidcc_client_context.hrl"]).
```
""").
?MODULEDOC(#{since => <<"3.0.0">>}).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-include_lib("jose/include/jose_jwk.hrl").

-export_type([authenticated_opts/0]).
-export_type([authenticated_t/0]).
-export_type([error/0]).
-export_type([opts/0]).
-export_type([t/0]).
-export_type([unauthenticated_opts/0]).
-export_type([unauthenticated_t/0]).

-export([from_configuration_worker/3]).
-export([from_configuration_worker/4]).
-export([from_manual/4]).
-export([from_manual/5]).
-export([apply_profiles/2]).

-type t() :: authenticated_t() | unauthenticated_t().

?DOC(#{since => <<"3.0.0">>}).
-type authenticated_t() :: #oidcc_client_context{
    provider_configuration :: oidcc_provider_configuration:t(),
    jwks :: jose_jwk:key(),
    client_id :: binary(),
    client_secret :: binary(),
    client_jwks :: jose_jwk:key() | none
}.

?DOC(#{since => <<"3.0.0">>}).
-type unauthenticated_t() :: #oidcc_client_context{
    provider_configuration :: oidcc_provider_configuration:t(),
    jwks :: jose_jwk:key(),
    client_id :: binary(),
    client_secret :: unauthenticated,
    client_jwks :: none
}.

?DOC(#{since => <<"3.0.0">>}).
-type authenticated_opts() :: #{
    client_jwks => jose_jwk:key()
}.

?DOC(#{since => <<"3.0.0">>}).
-type unauthenticated_opts() :: #{}.

?DOC(#{since => <<"3.0.0">>}).
-type opts() :: authenticated_opts() | unauthenticated_opts().

?DOC(#{since => <<"3.0.0">>}).
-type error() :: provider_not_ready.

?DOC("""
Create Client Context from a `m:oidcc_provider_configuration_worker`.

See `from_configuration_worker/4`.
""").
?DOC(#{since => <<"3.0.0">>}).
-spec from_configuration_worker
    (ProviderName, ClientId, ClientSecret) -> {ok, authenticated_t()} | {error, error()} when
        ProviderName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary();
    (ProviderName, ClientId, ClientSecret) -> {ok, unauthenticated_t()} | {error, error()} when
        ProviderName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: unauthenticated.
from_configuration_worker(ProviderName, ClientId, ClientSecret) ->
    from_configuration_worker(ProviderName, ClientId, ClientSecret, #{}).

?DOC("""
Create Client Context from a `m:oidcc_provider_configuration_worker`.

## Examples

```erlang
{ok, Pid} =
  oidcc_provider_configuration_worker:start_link(#{
    issuer => <<"https://login.salesforce.com">>
  }),

{ok, #oidcc_client_context{}} =
  oidcc_client_context:from_configuration_worker(Pid,
                                                 <<"client_id">>,
                                                 <<"client_secret">>).
```

```erlang
{ok, Pid} =
  oidcc_provider_configuration_worker:start_link(#{
    issuer => <<"https://login.salesforce.com">>,
    name => {local, salesforce_provider}
  }),

{ok, #oidcc_client_context{}} =
  oidcc_client_context:from_configuration_worker(
    salesforce_provider,
    <<"client_id">>,
    <<"client_secret">>,
    #{client_jwks => jose_jwk:generate_key(16)}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec from_configuration_worker
    (ProviderName, ClientId, ClientSecret, Opts) ->
        {ok, authenticated_t()} | {error, error()}
    when
        ProviderName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: authenticated_opts();
    (ProviderName, ClientId, ClientSecret, Opts) ->
        {ok, unauthenticated_t()} | {error, error()}
    when
        ProviderName :: gen_server:server_ref(),
        ClientId :: binary(),
        ClientSecret :: unauthenticated,
        Opts :: unauthenticated_opts().
from_configuration_worker(ProviderName, ClientId, ClientSecret, Opts) when is_pid(ProviderName) ->
    maybe
        #oidcc_provider_configuration{} =
            ProviderConfiguration ?=
                oidcc_provider_configuration_worker:get_provider_configuration(ProviderName),
        #jose_jwk{} = Jwks ?= oidcc_provider_configuration_worker:get_jwks(ProviderName),
        {ok,
            from_manual(
                ProviderConfiguration,
                Jwks,
                ClientId,
                ClientSecret,
                Opts
            )}
    else
        undefined -> {error, provider_not_ready}
    end;
from_configuration_worker(ProviderName, ClientId, ClientSecret, Opts) ->
    case erlang:whereis(ProviderName) of
        undefined ->
            {error, provider_not_ready};
        Pid ->
            from_configuration_worker(Pid, ClientId, ClientSecret, Opts)
    end.

?DOC("""
Create Client Context manually.

See `from_manual/5`.
""").
?DOC(#{since => <<"3.0.0">>}).
-spec from_manual
    (Configuration, Jwks, ClientId, ClientSecret) -> authenticated_t() when
        Configuration :: oidcc_provider_configuration:t(),
        Jwks :: jose_jwk:key(),
        ClientId :: binary(),
        ClientSecret :: binary();
    (Configuration, Jwks, ClientId, ClientSecret) -> unauthenticated_t() when
        Configuration :: oidcc_provider_configuration:t(),
        Jwks :: jose_jwk:key(),
        ClientId :: binary(),
        ClientSecret :: unauthenticated.
from_manual(Configuration, Jwks, ClientId, ClientSecret) ->
    from_manual(Configuration, Jwks, ClientId, ClientSecret, #{}).

?DOC("""
Create Client Context manually.

## Examples

```erlang
{ok, Configuration} =
  oidcc_provider_configuration:load_configuration(<<"https://login.salesforce.com">>, []),

#oidcc_provider_configuration{jwks_uri = JwksUri} = Configuration,

{ok, Jwks} = oidcc_provider_configuration:load_jwks(JwksUri, []).

#oidcc_client_context{} =
  oidcc_client_context:from_manual(
    Metadata,
    Jwks,
    <<"client_id">>,
    <<"client_secret">>,
    #{client_jwks => jose_jwk:generate_key(16)}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec from_manual
    (Configuration, Jwks, ClientId, ClientSecret, Opts) -> authenticated_t() when
        Configuration :: oidcc_provider_configuration:t(),
        Jwks :: jose_jwk:key(),
        ClientId :: binary(),
        ClientSecret :: binary(),
        Opts :: authenticated_opts();
    (Configuration, Jwks, ClientId, ClientSecret, Opts) -> unauthenticated_t() when
        Configuration :: oidcc_provider_configuration:t(),
        Jwks :: jose_jwk:key(),
        ClientId :: binary(),
        ClientSecret :: unauthenticated,
        Opts :: unauthenticated_opts().
from_manual(
    #oidcc_provider_configuration{} = Configuration,
    #jose_jwk{} = Jwks,
    ClientId,
    unauthenticated,
    _Opts
) when is_binary(ClientId) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        jwks = Jwks,
        client_id = ClientId,
        client_secret = unauthenticated
    };
from_manual(
    #oidcc_provider_configuration{} = Configuration,
    #jose_jwk{} = Jwks,
    ClientId,
    ClientSecret,
    Opts
) when is_binary(ClientId), is_binary(ClientSecret) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        jwks = Jwks,
        client_id = ClientId,
        client_secret = ClientSecret,
        client_jwks = maps:get(client_jwks, Opts, none)
    }.

?DOC("""
Apply OpenID Connect / OAuth2 Profiles to the context.

Currently, the only supported profiles are:
- `fapi2_security_profile` - https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html
- `fapi2_message_signing` - https://openid.bitbucket.io/fapi/fapi-2_0-message-signing.html

It returns an updated `t:t/0` record and a map of options to
be merged into the `m:oidcc_authorization` and `m:oidcc_token` functions.

## Examples

```erlang
ClientContext = #oidcc_client_context{} = oidcc_client_context:from_...(...),

{#oidcc_client_context{} = ClientContext1, Opts} = oidcc_client_context:apply_profiles(
  ClientContext,
  #{
    profiles => [fapi2_message_signing]
  }),

{ok, Uri} = oidcc_authorization:create_redirect_uri(
  ClientContext1,
  maps:merge(Opts, #{...})
).
```
""").
?DOC(#{since => <<"3.2.0">>}).
-spec apply_profiles(ClientContext, oidcc_profile:opts()) ->
    {ok, ClientContext, oidcc_profile:opts_no_profiles()} | {error, oidcc_profile:error()}
when
    ClientContext :: oidcc_client_context:t().
apply_profiles(ClientContext, Opts) ->
    oidcc_profile:apply_profiles(ClientContext, Opts).
