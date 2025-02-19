%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_logout).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("Logout from the OpenID Provider.").
?MODULEDOC(#{since => <<"3.0.0">>}).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").
-include("oidcc_token.hrl").

-export([initiate_url/3]).

-export_type([error/0]).
-export_type([initiate_url_opts/0]).

?DOC(#{since => <<"3.0.0">>}).
-type error() :: end_session_endpoint_not_supported.

?DOC("""
Configure Relaying Party initiated Logout URI.

See https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout.

## Parameters

* `logout_hint` - logout_hint to pass to the provider
* `post_logout_redirect_uri` - Post Logout Redirect URI to pass to the provider
* `state` - state to pass to the provider
* `ui_locales` - UI locales to pass to the provider
* `extra_query_params` - extra query params to add to the URI
""").
?DOC(#{since => <<"3.0.0">>}).
-type initiate_url_opts() :: #{
    logout_hint => binary(),
    post_logout_redirect_uri => uri_string:uri_string(),
    state => binary(),
    ui_locales => binary(),
    extra_query_params => oidcc_http_util:query_params()
}.

?DOC("""
Initiate URI for Relaying Party initiated Logout.

See https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout.

For a high level interface using `m:oidcc_provider_configuration_worker`
see `oidcc:initiate_logout_url/4`.

## Examples

```erlang
{ok, ClientContext} = oidcc_client_context:from_configuration_worker(
  provider_name,
  <<"client_id">>,
  unauthenticated
),

%% Get `Token` from `oidcc_token`

{ok, RedirectUri} =
  oidcc_logout:initiate_url(
    Token,
    ClientContext,
    #{post_logout_redirect_uri: <<"https://my.server/return">}
),

%% RedirectUri = https://my.provider/logout?id_token_hint=IDToken&client_id=ClientId&post_logout_redirect_uri=https%3A%2F%2Fmy.server%2Freturn
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec initiate_url(Token, ClientContext, Opts) ->
    {ok, uri_string:uri_string()} | {error, error()}
when
    Token :: IdToken | oidcc_token:t() | undefined,
    IdToken :: binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: initiate_url_opts().
initiate_url(#oidcc_token{id = #oidcc_token_id{token = IdToken}}, ClientContext, Opts) ->
    initiate_url(IdToken, ClientContext, Opts);
initiate_url(IdToken, ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId
    } = ClientContext,
    #oidcc_provider_configuration{end_session_endpoint = EndSessionEndpoint} =
        Configuration,

    QueryParams0 = [
        {"id_token_hint", IdToken},
        {"logout_hint", maps:get(logout_hint, Opts, undefined)},
        {"client_id", ClientId},
        {"post_logout_redirect_uri", maps:get(post_logout_redirect_uri, Opts, undefined)},
        {"state", maps:get(state, Opts, undefined)},
        {"ui_locales", maps:get(ui_locales, Opts, undefined)}
        | maps:get(extra_query_params, Opts, [])
    ],
    QueryParams1 = lists:filter(
        fun
            ({_Name, undefined}) -> false;
            ({_Name, _Value}) -> true
        end,
        QueryParams0
    ),

    case EndSessionEndpoint of
        undefined ->
            {error, end_session_endpoint_not_supported};
        Uri0 ->
            UriMap0 = uri_string:parse(Uri0),
            QueryString0 = maps:get(query, UriMap0, <<"">>),
            QueryParams = uri_string:dissect_query(QueryString0) ++ QueryParams1,
            QueryString = uri_string:compose_query(QueryParams),
            UriMap = maps:put(query, QueryString, UriMap0),
            Uri = uri_string:recompose(UriMap),
            {ok, Uri}
    end.
