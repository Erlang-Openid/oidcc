%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_logout_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

initiate_url_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),
    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    NormalConfiguration = Configuration#oidcc_provider_configuration{
        end_session_endpoint = <<"https://example.provider/logout">>
    },
    NormalClientContext = oidcc_client_context:from_manual(
        NormalConfiguration, Jwks, <<"client_id">>, unauthenticated
    ),

    QueryParamConfiguration = Configuration#oidcc_provider_configuration{
        end_session_endpoint = <<"https://example.provider/logout?query=param">>
    },
    QueryParamClientContext = oidcc_client_context:from_manual(
        QueryParamConfiguration, Jwks, <<"client_id">>, unauthenticated
    ),

    NoEndSessionEndpointConfiguration = Configuration#oidcc_provider_configuration{
        end_session_endpoint = undefined
    },
    NoEndSessionEndpointClientContext = oidcc_client_context:from_manual(
        NoEndSessionEndpointConfiguration, Jwks, <<"client_id">>, unauthenticated
    ),

    ?assertMatch(
        {error, end_session_endpoint_not_supported},
        oidcc_logout:initiate_url(<<"id_token">>, NoEndSessionEndpointClientContext, #{})
    ),

    {ok, NormalUri0} = oidcc_logout:initiate_url(
        #oidcc_token{id = #oidcc_token_id{token = <<"id_token">>}}, NormalClientContext, #{}
    ),
    ?assertEqual(
        <<"https://example.provider/logout?id_token_hint=id_token&client_id=client_id">>,
        iolist_to_binary(NormalUri0)
    ),

    {ok, NormalUri1} = oidcc_logout:initiate_url(undefined, NormalClientContext, #{}),
    ?assertEqual(
        <<"https://example.provider/logout?client_id=client_id">>, iolist_to_binary(NormalUri1)
    ),

    {ok, QueryParamsUri} = oidcc_logout:initiate_url(undefined, QueryParamClientContext, #{}),
    ?assertEqual(
        <<"https://example.provider/logout?query=param&client_id=client_id">>,
        iolist_to_binary(QueryParamsUri)
    ),

    ok.
