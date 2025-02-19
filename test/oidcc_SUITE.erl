%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_SUITE).

-export([all/0]).
-export([create_redirect_url/1]).
-export([end_per_suite/1]).
-export([initiate_logout_url/1]).
-export([init_per_suite/1]).
-export([introspect_token/1]).
-export([refresh_token/1]).
-export([retrieve_client_credentials_token/1]).
-export([retrieve_jwt_profile_token/1]).
-export([retrieve_token/1]).
-export([retrieve_userinfo/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [
        create_redirect_url,
        retrieve_token,
        retrieve_userinfo,
        refresh_token,
        initiate_logout_url,
        introspect_token,
        retrieve_jwt_profile_token,
        retrieve_client_credentials_token
    ].

init_per_suite(_Config) ->
    {ok, _} = application:ensure_all_started(oidcc),
    [].

end_per_suite(_Config) ->
    ok = application:stop(oidcc).

create_redirect_url(_Config) ->
    {ok, ConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://login.salesforce.com">>,
            name => {local, create_redirect_url_oidcc_SUITE}
        }),

    {ok, Url} =
        oidcc:create_redirect_url(
            ConfigurationPid,
            <<"client_id">>,
            <<"client_secret">>,
            #{redirect_uri => <<"https://my.server/return">>}
        ),

    ExpUrl =
        <<"https://login.salesforce.com/services/oauth2/authorize?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn">>,

    ?assertEqual(ExpUrl, iolist_to_binary(Url)),

    ok.

retrieve_token(_Config) ->
    {ok, ConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://login.salesforce.com">>,
            name => {local, create_redirect_url_oidcc_SUITE}
        }),

    {error, Reason} =
        oidcc:retrieve_token(
            <<"invalid_auth_code">>,
            ConfigurationPid,
            <<"client_id">>,
            <<"client_secret">>,
            #{redirect_uri => <<"https://my.server/return">>}
        ),

    ?assertMatch({http_error, 400, _}, Reason),

    ok.

retrieve_userinfo(_Config) ->
    {ok, ConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://login.salesforce.com">>,
            name => {local, create_redirect_url_oidcc_SUITE}
        }),

    {error, Reason} =
        oidcc:retrieve_userinfo(
            <<"invalid_auth_token">>,
            ConfigurationPid,
            <<"client_id">>,
            <<"client_secret">>,
            #{expected_subject => <<"some sub">>}
        ),

    ?assertMatch({http_error, 403, _}, Reason),

    ok.

refresh_token(_Config) ->
    {ok, ConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>,
            name => {local, create_redirect_url_oidcc_SUITE}
        }),

    {error, Reason} =
        oidcc:refresh_token(
            <<"invalid_refresh_token">>,
            ConfigurationPid,
            <<"client_id">>,
            <<"client_secret">>,
            #{expected_subject => <<"some sub">>}
        ),

    {error, Reason} =
        oidcc:refresh_token(
            #oidcc_token{
                refresh = #oidcc_token_refresh{token = <<"invalid_refresh_token">>},
                id = #oidcc_token_id{claims = #{<<"sub">> => <<"some sub">>}}
            },
            ConfigurationPid,
            <<"client_id">>,
            <<"client_secret">>,
            #{}
        ),

    ?assertMatch({http_error, 400, _}, Reason),

    ok.

introspect_token(_Config) ->
    {ok, ConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://login.salesforce.com">>,
            name => {local, create_redirect_url_oidcc_SUITE}
        }),

    {error, Reason} =
        oidcc:introspect_token(
            <<"invalid_access_token">>,
            ConfigurationPid,
            <<"client_id">>,
            <<"client_secret">>,
            #{}
        ),

    ?assertMatch({http_error, 401, _}, Reason),

    ok.

retrieve_jwt_profile_token(_Config) ->
    {ok, ZitadelConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>
        }),

    PrivDir = code:priv_dir(oidcc),

    {ok, KeyJson} = file:read_file(PrivDir ++ "/test/fixtures/zitadel-jwt-profile.json"),
    KeyMap = jose:decode(KeyJson),
    Key = jose_jwk:from_pem(maps:get(<<"key">>, KeyMap)),

    application:set_env(oidcc, max_clock_skew, 10),
    ?assertMatch(
        {ok, _},
        oidcc:jwt_profile_token(
            <<"231391584430604723">>,
            ZitadelConfigurationPid,
            <<"JWT Profile Test">>,
            <<"client_secret">>,
            Key,
            #{
                scope => [<<"openid">>, <<"urn:zitadel:iam:org:project:id:zitadel:aud">>],
                kid => maps:get(<<"keyId">>, KeyMap)
            }
        )
    ),
    application:unset_env(oidcc, max_clock_skew),

    ok.

retrieve_client_credentials_token(_Config) ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ZitadelConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>
        }),

    {ok, ZitadelClientCredentialsJson} = file:read_file(
        PrivDir ++ "/test/fixtures/zitadel-client-credentials.json"
    ),
    #{
        <<"clientId">> := ZitadelClientCredentialsClientId,
        <<"clientSecret">> := ZitadelClientCredentialsClientSecret
    } = jose:decode(ZitadelClientCredentialsJson),

    ?assertMatch(
        {ok, _},
        oidcc:client_credentials_token(
            ZitadelConfigurationPid,
            ZitadelClientCredentialsClientId,
            ZitadelClientCredentialsClientSecret,
            #{scope => [<<"openid">>]}
        )
    ),

    ok.

initiate_logout_url(_Config) ->
    {ok, ZitadelConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>
        }),

    {ok, Uri} = oidcc:initiate_logout_url(
        #oidcc_token{id = #oidcc_token_id{token = <<"id_token">>}},
        ZitadelConfigurationPid,
        <<"client_id">>,
        #{}
    ),
    ?assertEqual(
        <<"https://erlef-test-w4a8z2.zitadel.cloud/oidc/v1/end_session?id_token_hint=id_token&client_id=client_id">>,
        iolist_to_binary(Uri)
    ),

    ok.
