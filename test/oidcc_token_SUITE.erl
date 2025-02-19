%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_token_SUITE).

-export([all/0]).
-export([end_per_suite/1]).
-export([init_per_suite/1]).
-export([retrieves_client_credentials_token/1]).
-export([retrieves_jwt_profile_token/1]).
-export([validates_access_token/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").
-include_lib("stdlib/include/assert.hrl").

all() -> [retrieves_jwt_profile_token, retrieves_client_credentials_token, validates_access_token].

init_per_suite(_Config) ->
    {ok, _} = application:ensure_all_started(oidcc),
    [].

end_per_suite(_Config) ->
    ok.

retrieves_jwt_profile_token(_Config) ->
    {ok, SalesforceConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://login.salesforce.com">>
        }),

    {ok, ZitadelConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>
        }),

    {ok, SalesforceClientContext} = oidcc_client_context:from_configuration_worker(
        SalesforceConfigurationPid,
        <<"231391584430604723">>,
        <<"client_secret">>
    ),

    {ok, ZitadelClientContext} = oidcc_client_context:from_configuration_worker(
        ZitadelConfigurationPid,
        <<"JWT Profile Test">>,
        <<"client_secret">>
    ),

    PrivDir = code:priv_dir(oidcc),

    {ok, KeyJson} = file:read_file(PrivDir ++ "/test/fixtures/zitadel-jwt-profile.json"),
    KeyMap = jose:decode(KeyJson),
    Key = jose_jwk:from_pem(maps:get(<<"key">>, KeyMap)),

    ?assertMatch(
        {ok, #oidcc_token{}},
        oidcc_token:jwt_profile(<<"231391584430604723">>, ZitadelClientContext, Key, #{
            scope => [<<"openid">>, <<"urn:zitadel:iam:org:project:id:zitadel:aud">>],
            kid => maps:get(<<"keyId">>, KeyMap)
        })
    ),

    ?assertMatch(
        {error, {grant_type_not_supported, jwt_bearer}},
        oidcc_token:jwt_profile(<<"231391584430604723">>, SalesforceClientContext, Key, #{
            kid => maps:get(<<"keyId">>, KeyMap)
        })
    ),

    ok.

retrieves_client_credentials_token(_Config) ->
    PrivDir = code:priv_dir(oidcc),

    {ok, SalesforceConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://login.salesforce.com">>
        }),

    {ok, ZitadelConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://erlef-test-w4a8z2.zitadel.cloud">>
        }),

    {ok, SalesforceClientContext} = oidcc_client_context:from_configuration_worker(
        SalesforceConfigurationPid,
        <<"client_id">>,
        <<"client_secret">>
    ),

    {ok, ZitadelClientCredentialsJson} = file:read_file(
        PrivDir ++ "/test/fixtures/zitadel-client-credentials.json"
    ),
    #{
        <<"clientId">> := ZitadelClientCredentialsClientId,
        <<"clientSecret">> := ZitadelClientCredentialsClientSecret
    } = jose:decode(ZitadelClientCredentialsJson),

    {ok, ZitadelClientContext} = oidcc_client_context:from_configuration_worker(
        ZitadelConfigurationPid,
        ZitadelClientCredentialsClientId,
        ZitadelClientCredentialsClientSecret
    ),

    application:set_env(oidcc, max_clock_skew, 10),
    ?assertMatch(
        {error, {grant_type_not_supported, client_credentials}},
        oidcc_token:client_credentials(SalesforceClientContext, #{})
    ),

    ?assertMatch(
        {ok, #oidcc_token{}},
        oidcc_token:client_credentials(ZitadelClientContext, #{
            scope => [<<"openid">>, <<"profile">>]
        })
    ),
    application:unset_env(oidcc, max_clock_skew),

    ok.

validates_access_token(_Config) ->
    PrivDir = code:priv_dir(oidcc),
    Issuer = <<"https://erlef-test-w4a8z2.zitadel.cloud">>,

    {ok, ZitadelConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => Issuer
        }),

    {ok, ZitadelClientCredentialsJson} = file:read_file(
        PrivDir ++ "/test/fixtures/zitadel-client-credentials.json"
    ),
    #{
        <<"clientId">> := ZitadelClientCredentialsClientId,
        <<"clientSecret">> := ZitadelClientCredentialsClientSecret
    } = jose:decode(ZitadelClientCredentialsJson),

    {ok, ZitadelClientContext} = oidcc_client_context:from_configuration_worker(
        ZitadelConfigurationPid,
        ZitadelClientCredentialsClientId,
        ZitadelClientCredentialsClientSecret
    ),

    application:set_env(oidcc, max_clock_skew, 10),
    {ok, Token} = oidcc_token:client_credentials(ZitadelClientContext, #{
        scope => [<<"openid">>, <<"profile">>]
    }),

    #oidcc_token{access = #oidcc_token_access{token = AccessToken}} = Token,
    ?assertMatch(
        {ok, #{
            <<"iss">> := Issuer,
            <<"aud">> := [ZitadelClientCredentialsClientId]
        }},
        oidcc_token:validate_jwt(AccessToken, ZitadelClientContext, #{signing_algs => [<<"RS256">>]})
    ),
    application:unset_env(oidcc, max_clock_skew),

    ok.
