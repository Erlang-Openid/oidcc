<div style="margin-right: 15px; float: left;">
  <img
    align="left"
    src="assets/logo.svg"
    alt="OpenID Connect Logo"
    width="170px"
  />
</div>

# oidcc

OpenID Connect client library for Erlang.

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![Main Branch](https://github.com/erlef/oidcc/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/erlef/oidcc/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/oidcc.svg)](https://hex.pm/packages/oidcc)
[![Total Download](https://img.shields.io/hexpm/dt/oidcc.svg)](https://hex.pm/packages/oidcc)
[![License](https://img.shields.io/hexpm/l/oidcc.svg)](https://github.com/erlef/oidcc/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/erlef/oidcc.svg)](https://github.com/erlef/oidcc/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/erlef/oidcc/badge.svg?branch=main)](https://coveralls.io/github/erlef/oidcc?branch=main)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9602/badge)](https://www.bestpractices.dev/projects/9602)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/erlef/oidcc/badge)](https://scorecard.dev/viewer/?uri=github.com/erlef/oidcc)

<br clear="left"/>

<picture style="margin-right: 15px; float: left;">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/certified-dark.svg"
    width="170px"
    align="left"
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="assets/certified-light.svg"
    width="170px"
    align="left"
  />
  <img
    src="assets/certified-light.svg"
    alt="OpenID Connect Certified Logo"
    width="170px"
    align="left"
  />
</picture>

OpenID Certified by [Jonatan Männchen](https://github.com/maennchen) at the
[Erlang Ecosystem Foundation](https://github.com/erlef) of multiple Relaying
Party conformance profiles of the OpenID Connect protocol:
For details, check the
[Conformance Test Suite](https://github.com/erlef/oidcc_conformance).

<br clear="left"/>

<picture style="margin-right: 15px; float: left;">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/erlef-logo-dark.svg"
    width="170px"
    align="left"
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="assets/erlef-logo-light.svg"
    width="170px"
    align="left"
  />
  <img
    src="assets/erlef-logo-light.svg"
    alt="Erlang Ecosystem Foundation Logo"
    width="170px"
    align="left"
  />
</picture>

The refactoring for `v3` and the certification is funded as an
[Erlang Ecosystem Foundation](https://erlef.org/) stipend entered by the
[Security Working Group](https://erlef.org/wg/security).

<br clear="left"/>


<picture style="margin-right: 15px; float: left;">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="https://security-audit-logo.s3.eu-central-1.amazonaws.com/image_safe_logo_dark.png"
    width="170px"
    align="left"
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="https://security-audit-logo.s3.eu-central-1.amazonaws.com/image_safe_logo_light.png"
    width="170px"
    align="left"
  />
  <img
    src="https://security-audit-logo.s3.eu-central-1.amazonaws.com/image_safe_logo_light.png"
    alt="Security Audit For Erlang and Elixir"
    width="170px"
    align="left"
  />
</picture>

A security audit was performed by [SAFE-Erlang-Elixir](https://github.com/SAFE-Erlang-Elixir) more info [HERE](https://www.erlang-solutions.com/landings/security-audit-for-erlang-2/).

<br clear="left"/>

## Supported Features

* [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
  (`[ISSUER]/.well-known/openid-configuration`)
* [Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
* Authorization (Code Flow)
  * [Request Object](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject)
  * [PKCE](https://oauth.net/2/pkce/)
  * [Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
  * [Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
* Token
  * Authorization: `client_secret_basic`, `client_secret_post`,
    `client_secret_jwt`, and `private_key_jwt`
  * Grant Types: `authorization_code`, `refresh_token`, `jwt_bearer`, and
    `client_credentials`
  * Automatic JWK Refreshing when needed
* Userinfo
  * [JWT Response](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)
  * [Aggregated and Distributed Claims](https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
* [Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
* Logout
  * [RP-Initiated](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
* [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm-final.html)
* [Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
* [OAuth 2 Purpose Request Parameter](https://cdn.connectid.com.au/specifications/oauth2-purpose-01.html)
* Profiles
  * [FAPI 2.0 Security Profile](https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html)
  * [FAPI 2.0 Message Signing](https://openid.bitbucket.io/fapi/fapi-2_0-message-signing.html)

## Setup

**Please note that the minimum supported Erlang OTP version is OTP26.**

<!-- tabs-open -->

### Erlang

**directly**

```erlang
{ok, Pid} =
    oidcc_provider_configuration_worker:start_link(#{
        issuer => <<"https://accounts.google.com">>,
        name => {local, google_config_provider}
    }).
```

**via `supervisor`**

```erlang
-behaviour(supervisor).

%% ...

init(_Args) ->
    SupFlags = #{strategy => one_for_one},
    ChildSpecs = [
        #{
            id => oidcc_provider_configuration_worker,
            start =>
                {oidcc_provider_configuration_worker, start_link, [
                    #{
                        issuer => "https://accounts.google.com",
                        name => {local, myapp_oidcc_config_provider}
                    }
                ]},
            shutdown => brutal_kill
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.
```

### Elixir

**directly**

```elixir
{:ok, _pid} =
  Oidcc.ProviderConfiguration.Worker.start_link(%{
    issuer: "https://accounts.google.com",
    name: Myapp.OidccConfigProvider
  })
```

**via `Supervisor`**

```elixir
Supervisor.init(
  [
    {Oidcc.ProviderConfiguration.Worker,
     %{
       issuer: "https://accounts.google.com",
       name: Myapp.OidccConfigProvider
     }}
  ],
  strategy: :one_for_one
)
```

**using [`igniter`](https://hex.pm/packages/igniter)**

```bash
mix oidcc.gen.provider_configuration_worker \
  --name MyApp.OidccConfigProvider \
  --issuer https://accounts.google.com
```

<!-- tabs-close -->

## Usage

<!-- tabs-open -->

### Companion libraries

`oidcc` offers integrations for various libraries:

<!-- TODO: Uncomment when available -->

- [`oidcc_cowboy`](https://hex.pm/packages/oidcc_cowboy) - Integrations for
  [`cowboy`](https://hex.pm/packages/cowboy)
- [`oidcc_plug`](https://hex.pm/packages/oidcc_plug) - Integrations for
  [`plug`](https://hex.pm/packages/plug) and
  [`phoenix`](https://hex.pm/packages/phoenix)
- [`ueberauth_oidcc`](https://hex.pm/packages/ueberauth_oidcc) - Integration for
  [`ueberauth`](https://hex.pm/packages/ueberauth)

### Erlang

```erlang
%% Create redirect URI for authorization
{ok, RedirectUri} = oidcc:create_redirect_url(
    myapp_oidcc_config_provider,
    <<"client_id">>,
    <<"client_secret">>,
    #{redirect_uri => <<"https://example.com/callback">>}
),

%% Redirect user to `RedirectUri`

%% Retrieve `code` query / form param from redirect back

%% Exchange code for token
{ok, Token} =
    oidcc:retrieve_token(
        AuthCode,
        myapp_oidcc_config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{redirect_uri => <<"https://example.com/callback">>}
    ),

%% Load userinfo for token
{ok, Claims} =
    oidcc:retrieve_userinfo(
        Token,
        myapp_oidcc_config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ),

%% Load introspection for access token
{ok, Introspection} =
    oidcc:introspect_token(
        Token,
        myapp_oidcc_config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ),

%% Refresh token when it expires
{ok, RefreshedToken} =
    oidcc:refresh_token(
        Token,
        myapp_oidcc_config_provider,
        <<"client_id">>,
        <<"client_secret">>,
        #{}
    ).
```

for more details, see https://hexdocs.pm/oidcc/oidcc.html

### Elixir

```elixir
# Create redirect URI for authorization
{:ok, redirect_uri} =
  Oidcc.create_redirect_url(
    Myapp.OidccConfigProvider,
    "client_id",
    "client_secret",
    %{redirect_uri: "https://example.com/callback"}
  )

# Redirect user to `redirect_uri`

# Retrieve `code` query / form param from redirect back

# Exchange code for token
{:ok, token} =
  Oidcc.retrieve_token(
    auth_code,
    Myapp.OidccConfigProvider,
    "client_id",
    "client_secret",
    %{redirect_uri: "https://example.com/callback"}
  )

# Load userinfo for token
{:ok, claims} =
  Oidcc.retrieve_userinfo(
    token,
    Myapp.OidccConfigProvider,
    "client_id",
    "client_secret",
    %{expected_subject: "sub"}
  )

# Load introspection for access token
{:ok, introspection} =
  Oidcc.introspect_token(
    token,
    Myapp.OidccConfigProvider,
    "client_id",
    "client_secret"
  )

# Refresh token when it expires
{:ok, refreshed_token} =
  Oidcc.refresh_token(
    token,
    Myapp.OidccConfigProvider,
    "client_id",
    "client_secret"
  )
```

for more details, see https://hexdocs.pm/oidcc/Oidcc.html

<!-- tabs-close -->
