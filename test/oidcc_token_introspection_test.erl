%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_token_introspection_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").
-include_lib("oidcc/include/oidcc_token_introspection.hrl").

introspect_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{introspection_endpoint = IntrospectionEndpoint} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    AccessToken = <<"access_token">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ok = meck:new(oidcc_http_util, [passthrough]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _TelemetryOpts,
            _RequestOpts
        ) ->
            IntrospectionEndpoint = ReqEndpoint,
            {ok,
                {
                    {json, #{
                        <<"active">> => true,
                        <<"client_id">> => ClientId,
                        <<"extra">> => <<"value">>
                    }},
                    []
                }}
        end,
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token_introspection{active = true, extra = #{<<"extra">> := <<"value">>}}},
        oidcc_token_introspection:introspect(
            AccessToken,
            ClientContext,
            #{}
        )
    ),

    ?assertMatch(
        {ok, #oidcc_token_introspection{active = true}},
        oidcc_token_introspection:introspect(
            #oidcc_token{access = #oidcc_token_access{token = AccessToken}},
            ClientContext,
            #{}
        )
    ),

    ?assertMatch(
        {ok, #oidcc_token_introspection{active = true}},
        oidcc_token_introspection:introspect(
            #oidcc_token{access = #oidcc_token_access{token = AccessToken}},
            ClientContext,
            #{client_self_only => true}
        )
    ),

    true = meck:validate(oidcc_http_util),

    meck:unload(oidcc_http_util),

    ok.

introspect_inactive_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{introspection_endpoint = IntrospectionEndpoint} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    AccessToken = <<"access_token">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ok = meck:new(oidcc_http_util, [passthrough]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _TelemetryOpts,
            _RequestOpts
        ) ->
            IntrospectionEndpoint = ReqEndpoint,
            {ok, {{json, #{<<"active">> => false, <<"client_id">> => ClientId}}, []}}
        end,
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token_introspection{active = false}},
        oidcc_token_introspection:introspect(
            AccessToken,
            ClientContext,
            #{}
        )
    ),

    true = meck:validate(oidcc_http_util),

    meck:unload(oidcc_http_util),

    ok.

introspection_not_supported_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Configuration = Configuration0#oidcc_provider_configuration{
        introspection_endpoint = undefined
    },

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    AccessToken = <<"access_token">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ?assertMatch(
        {error, introspection_not_supported},
        oidcc_token_introspection:introspect(
            AccessToken,
            ClientContext,
            #{}
        )
    ),

    ok.

introspection_invalid_client_id_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{introspection_endpoint = IntrospectionEndpoint} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    AccessToken = <<"access_token">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwks, <<"other client id">>, ClientSecret
    ),

    ok = meck:new(oidcc_http_util, [passthrough]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _TelemetryOpts,
            _RequestOpts
        ) ->
            IntrospectionEndpoint = ReqEndpoint,
            {ok, {{json, #{<<"active">> => true, <<"client_id">> => ClientId}}, []}}
        end,
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    ?assertMatch(
        {error, client_id_mismatch},
        oidcc_token_introspection:introspect(
            AccessToken,
            ClientContext,
            #{}
        )
    ),

    true = meck:validate(oidcc_http_util),

    meck:unload(oidcc_http_util),

    ok.

introspection_issuer_client_id_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{
            introspection_endpoint = IntrospectionEndpoint,
            issuer = Issuer
        } =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    OtherClientId = <<"other_client_id">>,
    MyClientId = <<"my_client_id">>,
    ClientSecret = <<"client_secret">>,
    AccessToken = <<"access_token">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwks, MyClientId, ClientSecret
    ),

    ok = meck:new(oidcc_http_util, [passthrough]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _TelemetryOpts,
            _RequestOpts
        ) ->
            IntrospectionEndpoint = ReqEndpoint,
            {ok,
                {
                    {json, #{
                        <<"active">> => true, <<"client_id">> => OtherClientId, <<"iss">> => Issuer
                    }},
                    []
                }}
        end,
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token_introspection{active = true, client_id = OtherClientId, iss = Issuer}},
        oidcc_token_introspection:introspect(
            #oidcc_token{access = #oidcc_token_access{token = AccessToken}},
            ClientContext,
            #{client_self_only => false}
        )
    ),

    ?assertMatch(
        {error, client_id_mismatch},
        oidcc_token_introspection:introspect(
            AccessToken,
            ClientContext,
            #{client_self_only => true}
        )
    ),

    true = meck:validate(oidcc_http_util),

    meck:unload(oidcc_http_util),

    ok.
