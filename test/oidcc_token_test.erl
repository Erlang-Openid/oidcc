%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_token_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

retrieve_none_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorithm for test
    jose:unsecured_signing(true),

    {ok, _} = application:ensure_all_started(oidcc),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [
                [oidcc, request_token, start],
                [oidcc, request_token, stop]
            ]
        ),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),
    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [<<"client_secret_basic">>, "unsupported"]
        },

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    JwkSet = #jose_jwk{keys = {jose_jwk_set, [Jwks]}},

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10
        },

    Jwk = jose_jwk:generate_key(16),
    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"none">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"expires_in">> => <<"3600">>
        }),

    ClientContext = oidcc_client_context:from_manual(Configuration, JwkSet, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            ?assertEqual(<<TokenEndpoint/binary, "?foo=bar">>, iolist_to_binary(ReqTokenEndpoint)),
            ?assertMatch({"authorization", _}, proplists:lookup("authorization", Header)),
            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"redirect_uri">> := LocalEndpoint,
                    <<"foo">> := <<"bar">>
                },
                maps:from_list(uri_string:dissect_query(Body))
            ),
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    jose:unsecured_signing(false),

    ?assertMatch(
        {error,
            {none_alg_used, #oidcc_token{
                id = #oidcc_token_id{token = Token, claims = Claims},
                access = #oidcc_token_access{token = AccessToken, expires = 3600},
                refresh = none,
                scope = [<<"profile">>, <<"openid">>]
            }}},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{
                redirect_uri => LocalEndpoint,
                url_extension => [{<<"foo">>, <<"bar">>}],
                body_extension => [{<<"foo">>, <<"bar">>}]
            }
        )
    ),

    receive
        {[oidcc, request_token, start], TelemetryRef, #{}, #{
            issuer := <<"https://my.provider">>,
            client_id := ClientId
        }} ->
            ok
    after 2_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

retrieve_rs256_with_rotation_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [
                [oidcc, request_token, start],
                [oidcc, request_token, stop]
            ]
        ),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [
                <<"client_secret_post">>, <<"client_secret_basic">>
            ]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    JwkBeforeRefresh0 = jose_jwk:generate_key(16),
    JwkBeforeRefresh = JwkBeforeRefresh0#jose_jwk{fields = #{<<"kid">> => <<"kid1">>}},

    JwkAfterRefresh0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    JwkAfterRefresh = JwkAfterRefresh0#jose_jwk{fields = #{<<"kid">> => <<"kid2">>}},

    RefreshJwksFun = fun(_OldJwk, <<"kid2">>) -> {ok, JwkAfterRefresh} end,

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>, <<"kid">> => <<"kid2">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(JwkAfterRefresh, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(
        Configuration, JwkBeforeRefresh, ClientId, ClientSecret
    ),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            ?assertMatch(none, proplists:lookup("authorization", Header)),
            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"redirect_uri">> := LocalEndpoint,
                    <<"client_id">> := ClientId,
                    <<"client_secret">> := ClientSecret
                },
                maps:from_list(uri_string:dissect_query(Body))
            ),
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint, refresh_jwks => RefreshJwksFun}
        )
    ),

    receive
        {[oidcc, request_token, start], TelemetryRef, #{}, #{
            issuer := <<"https://my.provider">>,
            client_id := ClientId
        }} ->
            ok
    after 2_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

retrieve_hs256_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_oct(<<"at_least_32_character_client_secret">>),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"HS256">>},
    {_Jws, Token} = jose_jws:compact(jose_jwt:sign(Jwk, Jws, Jwt)),

    OtherJwk = jose_jwk:from_file(PrivDir ++ "/test/fixtures/openid-certification-jwks.json"),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(
        Configuration, OtherJwk, ClientId, ClientSecret
    ),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

retrieve_hs256_with_max_clock_skew_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"nbf">> => erlang:system_time(second) + 5,
            <<"iat">> => erlang:system_time(second) + 5,
            <<"exp">> => erlang:system_time(second) + 15,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_oct(<<"at_least_32_character_client_secret">>),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"HS256">>},
    {_Jws, Token} = jose_jws:compact(jose_jwt:sign(Jwk, Jws, Jwt)),

    OtherJwk = jose_jwk:from_file(PrivDir ++ "/test/fixtures/openid-certification-jwks.json"),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(
        Configuration, OtherJwk, ClientId, ClientSecret
    ),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {error, token_not_yet_valid},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    application:set_env(oidcc, max_clock_skew, 10),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    application:unset_env(oidcc, max_clock_skew),

    ok.

auth_method_client_secret_jwt_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [
                <<"client_secret_jwt">>, <<"client_secret_basic">>
            ],
            token_endpoint_auth_signing_alg_values_supported = [<<"HS256">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            ?assertMatch(none, proplists:lookup("authorization", Header)),
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"client_id">> := ClientId,
                    <<"client_assertion_type">> :=
                        <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>,
                    <<"client_assertion">> := _
                },
                BodyMap
            ),

            ClientAssertion = maps:get(<<"client_assertion">>, BodyMap),

            {true, ClientAssertionJwt, ClientAssertionJws} = jose_jwt:verify(
                jose_jwk:from_oct(ClientSecret), ClientAssertion
            ),

            ?assertMatch(#jose_jws{alg = {jose_jws_alg_hmac, 'HS256'}}, ClientAssertionJws),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"aud">> := Issuer,
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"iss">> := ClientId,
                        <<"jti">> := _,
                        <<"nbf">> := _,
                        <<"sub">> := ClientId
                    }
                },
                ClientAssertionJwt
            ),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken, type = <<"Bearer">>},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

auth_method_client_secret_jwt_with_max_clock_skew_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [
                <<"client_secret_jwt">>, <<"client_secret_basic">>
            ],
            token_endpoint_auth_signing_alg_values_supported = [<<"HS256">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, _, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ClientAssertion = maps:get(<<"client_assertion">>, BodyMap),

            {true, ClientAssertionJwt, _} = jose_jwt:verify(
                jose_jwk:from_oct(ClientSecret), ClientAssertion
            ),

            #jose_jwt{
                fields = #{
                    <<"nbf">> := ClientTokenNbf
                }
            } = ClientAssertionJwt,

            ?assert(ClientTokenNbf < os:system_time(seconds) - 5),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    application:set_env(oidcc, max_clock_skew, 10),

    oidcc_token:retrieve(
        AuthCode,
        ClientContext,
        #{redirect_uri => LocalEndpoint}
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    application:unset_env(oidcc, max_clock_skew),

    ok.

auth_method_private_key_jwt_no_supported_alg_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [
                <<"private_key_jwt">>, <<"client_secret_post">>
            ],
            token_endpoint_auth_signing_alg_values_supported = [<<"unsupported">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,

            ?assertMatch(none, proplists:lookup("authorization", Header)),

            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"client_id">> := ClientId,
                    <<"client_secret">> := ClientSecret
                },
                maps:from_list(uri_string:dissect_query(Body))
            ),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

auth_method_private_key_jwt_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [<<"private_key_jwt">>],
            token_endpoint_auth_signing_alg_values_supported = [<<"RS256">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientJwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = ClientJwk0#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret, #{
        client_jwks => ClientJwk
    }),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            ?assertMatch(none, proplists:lookup("authorization", Header)),
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"client_id">> := ClientId,
                    <<"client_assertion_type">> :=
                        <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>,
                    <<"client_assertion">> := _
                },
                BodyMap
            ),

            ClientAssertion = maps:get(<<"client_assertion">>, BodyMap),

            {true, ClientAssertionJwt, ClientAssertionJws} = jose_jwt:verify(
                ClientJwk, ClientAssertion
            ),

            ?assertMatch(
                #jose_jws{alg = {_, 'RS256'}}, ClientAssertionJws
            ),

            #jose_jws{fields = ClientAssertionJwsFields} = ClientAssertionJws,
            ?assertMatch(
                #{
                    <<"kid">> := <<"private_kid">>
                },
                ClientAssertionJwsFields
            ),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"aud">> := Issuer,
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"iss">> := ClientId,
                        <<"jti">> := _,
                        <<"nbf">> := _,
                        <<"sub">> := ClientId
                    }
                },
                ClientAssertionJwt
            ),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.
auth_method_private_key_jwt_override_claims_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [<<"private_key_jwt">>],
            token_endpoint_auth_signing_alg_values_supported = [<<"RS256">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientJwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = ClientJwk0#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret, #{
        client_jwks => ClientJwk
    }),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            ?assertMatch(none, proplists:lookup("authorization", Header)),
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"client_id">> := ClientId,
                    <<"client_assertion_type">> :=
                        <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>,
                    <<"client_assertion">> := _
                },
                BodyMap
            ),

            ClientAssertion = maps:get(<<"client_assertion">>, BodyMap),

            {true, ClientAssertionJwt, ClientAssertionJws} = jose_jwt:verify(
                ClientJwk, ClientAssertion
            ),

            ?assertMatch(
                #jose_jws{alg = {_, 'RS256'}}, ClientAssertionJws
            ),

            #jose_jws{fields = ClientAssertionJwsFields} = ClientAssertionJws,
            ?assertMatch(
                #{
                    <<"kid">> := <<"private_kid">>
                },
                ClientAssertionJwsFields
            ),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"aud">> := <<"overridden">>,
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"iss">> := ClientId,
                        <<"jti">> := _,
                        <<"nbf">> := _,
                        <<"sub">> := ClientId,
                        <<"extra">> := <<"claim">>
                    }
                },
                ClientAssertionJwt
            ),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{
                redirect_uri => LocalEndpoint,
                token_request_claims => #{<<"aud">> => <<"overridden">>, <<"extra">> => <<"claim">>}
            }
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

auth_method_private_key_jwt_with_dpop_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [<<"private_key_jwt">>],
            token_endpoint_auth_signing_alg_values_supported = [<<"RS256">>],
            dpop_signing_alg_values_supported = [<<"RS256">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientJwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = ClientJwk0#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret, #{
        client_jwks => ClientJwk
    }),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            ?assertMatch(none, proplists:lookup("authorization", Header)),
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"client_id">> := ClientId,
                    <<"client_assertion_type">> :=
                        <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>,
                    <<"client_assertion">> := _
                },
                BodyMap
            ),

            ClientAssertion = maps:get(<<"client_assertion">>, BodyMap),

            {true, ClientAssertionJwt, ClientAssertionJws} = jose_jwt:verify(
                ClientJwk, ClientAssertion
            ),

            ?assertMatch(
                #jose_jws{alg = {_, 'RS256'}}, ClientAssertionJws
            ),

            #jose_jws{fields = ClientAssertionJwsFields} = ClientAssertionJws,
            ?assertMatch(
                #{
                    <<"kid">> := <<"private_kid">>
                },
                ClientAssertionJwsFields
            ),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"aud">> := Issuer,
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"iss">> := ClientId,
                        <<"jti">> := _,
                        <<"nbf">> := _,
                        <<"sub">> := ClientId
                    }
                },
                ClientAssertionJwt
            ),

            {_, DpopProof} = proplists:lookup("dpop", Header),

            {true, DpopJwt, DpopJws} = jose_jwt:verify(
                ClientJwk, DpopProof
            ),

            ?assertMatch(
                #jose_jws{alg = {_, 'RS256'}}, DpopJws
            ),

            #jose_jws{fields = DpopJwsFields} = DpopJws,
            ?assertMatch(
                #{
                    <<"kid">> := <<"private_kid">>,
                    <<"typ">> := <<"dpop+jwt">>,
                    <<"jwk">> := _
                },
                DpopJwsFields
            ),

            #{<<"jwk">> := DpopPublicKeyMap} = DpopJwsFields,
            ?assertEqual(
                DpopPublicKeyMap,
                element(2, jose_jwk:to_public_map(ClientJwk))
            ),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"jti">> := _,
                        <<"htm">> := <<"POST">>,
                        <<"htu">> := TokenEndpoint
                    }
                },
                DpopJwt
            ),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

auth_method_private_key_jwt_with_dpop_and_nonce_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [<<"private_key_jwt">>],
            token_endpoint_auth_signing_alg_values_supported = [<<"RS256">>],
            dpop_signing_alg_values_supported = [<<"RS256">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    DpopNonce = <<"dpop_nonce">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    DpopNonceError = jsx:encode(#{
        <<"error">> => <<"use_dpop_nonce">>,
        <<"error_description">> =>
            <<"Authorization server requires nonce in DPoP proof">>
    }),

    ClientJwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = ClientJwk0#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret, #{
        client_jwks => ClientJwk
    }),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            ?assertMatch(none, proplists:lookup("authorization", Header)),
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"client_id">> := ClientId,
                    <<"client_assertion_type">> :=
                        <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>,
                    <<"client_assertion">> := _
                },
                BodyMap
            ),

            ClientAssertion = maps:get(<<"client_assertion">>, BodyMap),

            {true, ClientAssertionJwt, ClientAssertionJws} = jose_jwt:verify(
                ClientJwk, ClientAssertion
            ),

            ?assertMatch(
                #jose_jws{alg = {_, 'RS256'}}, ClientAssertionJws
            ),

            #jose_jws{fields = ClientAssertionJwsFields} = ClientAssertionJws,
            ?assertMatch(
                #{
                    <<"kid">> := <<"private_kid">>
                },
                ClientAssertionJwsFields
            ),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"aud">> := Issuer,
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"iss">> := ClientId,
                        <<"jti">> := _,
                        <<"nbf">> := _,
                        <<"sub">> := ClientId
                    }
                },
                ClientAssertionJwt
            ),

            {_, DpopProof} = proplists:lookup("dpop", Header),

            {true, DpopJwt, DpopJws} = jose_jwt:verify(
                ClientJwk, DpopProof
            ),

            ?assertMatch(
                #jose_jws{alg = {_, 'RS256'}}, DpopJws
            ),

            #jose_jws{fields = DpopJwsFields} = DpopJws,
            ?assertMatch(
                #{
                    <<"kid">> := <<"private_kid">>,
                    <<"typ">> := <<"dpop+jwt">>,
                    <<"jwk">> := _
                },
                DpopJwsFields
            ),

            #{<<"jwk">> := DpopPublicKeyMap} = DpopJwsFields,
            ?assertEqual(
                DpopPublicKeyMap,
                element(2, jose_jwk:to_public_map(ClientJwk))
            ),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"jti">> := _,
                        <<"htm">> := <<"POST">>,
                        <<"htu">> := TokenEndpoint
                    }
                },
                DpopJwt
            ),

            case DpopJwt of
                #jose_jwt{
                    fields = #{
                        <<"nonce">> := DpopNonce
                    }
                } ->
                    {ok, {
                        {"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData
                    }};
                _ ->
                    {ok, {
                        {"HTTP/1.1", 400, "OK"},
                        [
                            {"content-type", "application/json"},
                            {"dpop-nonce", binary_to_list(DpopNonce)}
                        ],
                        DpopNonceError
                    }}
            end
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

auth_method_private_key_jwt_with_invalid_dpop_nonce_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        token_endpoint_auth_methods_supported = [<<"private_key_jwt">>],
        token_endpoint_auth_signing_alg_values_supported = [<<"RS256">>],
        dpop_signing_alg_values_supported = [<<"RS256">>]
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    DpopNonce = <<"dpop_nonce">>,
    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    DpopNonceError = jsx:encode(#{
        <<"error">> => <<"use_dpop_nonce">>,
        <<"error_description">> =>
            <<"Authorization server requires nonce in DPoP proof">>
    }),

    ClientJwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = ClientJwk0#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret, #{
        client_jwks => ClientJwk
    }),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {_Endpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            {ok, {
                {"HTTP/1.1", 400, "OK"},
                [{"content-type", "application/json"}, {"dpop-nonce", DpopNonce}],
                DpopNonceError
            }}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {error, _},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{
                redirect_uri => LocalEndpoint,
                dpop_nonce => <<"invalid_nonce">>
            }
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

auth_method_client_secret_jwt_no_alg_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        token_endpoint_auth_methods_supported = [
            <<"client_secret_jwt">>
        ],
        token_endpoint_auth_signing_alg_values_supported = undefined
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret),

    ?assertMatch(
        {error, no_supported_auth_method},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    ok.

preferred_auth_methods_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    #oidcc_provider_configuration{token_endpoint = TokenEndpoint, issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [
                <<"client_secret_jwt">>, <<"client_secret_basic">>
            ],
            token_endpoint_auth_signing_alg_values_supported = [<<"HS256">>]
        },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    RefreshToken = <<"refresh_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>,
            <<"refresh_token">> => RefreshToken
        }),

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqTokenEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            TokenEndpoint = ReqTokenEndpoint,
            ?assertMatch({"authorization", _}, proplists:lookup("authorization", Header)),
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ?assertMatch(
                #{
                    <<"grant_type">> := <<"authorization_code">>,
                    <<"code">> := AuthCode,
                    <<"redirect_uri">> := LocalEndpoint
                },
                BodyMap
            ),

            ?assertMatch(none, maps:get("client_assertion", BodyMap, none)),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{
            id = #oidcc_token_id{token = Token, claims = Claims},
            access = #oidcc_token_access{token = AccessToken},
            refresh = #oidcc_token_refresh{token = RefreshToken},
            scope = [<<"profile">>, <<"openid">>]
        }},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint, preferred_auth_methods => [client_secret_basic]}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

authorization_headers_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    SigningAlg = [<<"RS256">>],

    Configuration = Configuration0#oidcc_provider_configuration{
        dpop_signing_alg_values_supported = SigningAlg
    },

    Jwk = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = ClientJwk0#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },
    {_, ClientPublicJwk} = jose_jwk:to_public_map(ClientJwk),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,
    Endpoint = <<"https://my.server/auth">>,
    AccessToken = <<"access_token">>,
    AccessTokenHash = base64:encode(crypto:hash(sha256, AccessToken), #{
        mode => urlsafe, padding => false
    }),

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret, #{
        client_jwks => ClientJwk
    }),

    AccessTokenRecord = #oidcc_token_access{token = AccessToken, type = <<"DPoP">>},

    HeaderMap = oidcc_token:authorization_headers(AccessTokenRecord, get, Endpoint, ClientContext),
    HeaderMapWithNonce = oidcc_token:authorization_headers(
        AccessTokenRecord, post, Endpoint, ClientContext, #{dpop_nonce => <<"dpop_nonce">>}
    ),

    ?assertMatch(
        #{
            <<"authorization">> := <<"DPoP access_token">>,
            <<"dpop">> := _
        },
        HeaderMap
    ),

    ?assertMatch(
        #{
            <<"authorization">> := <<"DPoP access_token">>,
            <<"dpop">> := _
        },
        HeaderMapWithNonce
    ),

    #{<<"dpop">> := DpopProof} = HeaderMap,
    #{<<"dpop">> := DpopProofWithNonce} = HeaderMapWithNonce,

    ?assertMatch(
        {ok, _},
        oidcc_jwt_util:verify_signature(DpopProof, SigningAlg, ClientJwk)
    ),
    ?assertMatch(
        {ok, _},
        oidcc_jwt_util:verify_signature(DpopProofWithNonce, SigningAlg, ClientJwk)
    ),

    {ok, {DpopJwt, DpopJws}} = oidcc_jwt_util:verify_signature(DpopProof, SigningAlg, ClientJwk),
    {ok, {DpopJwtWithNonce, DpopJwsWithNonce}} = oidcc_jwt_util:verify_signature(
        DpopProofWithNonce, SigningAlg, ClientJwk
    ),

    ?assertMatch(
        #jose_jws{
            fields = #{
                <<"typ">> := <<"dpop+jwt">>,
                <<"kid">> := <<"private_kid">>,
                <<"jwk">> := ClientPublicJwk
            }
        },
        DpopJws
    ),
    ?assertEqual(
        DpopJws,
        DpopJwsWithNonce
    ),

    ?assertMatch(
        #jose_jwt{
            fields = #{
                <<"jti">> := _,
                <<"htm">> := <<"GET">>,
                <<"htu">> := Endpoint,
                <<"iat">> := _,
                <<"exp">> := _,
                <<"ath">> := AccessTokenHash
            }
        },
        DpopJwt
    ),
    ?assertMatch(
        #jose_jwt{
            fields = #{
                <<"jti">> := _,
                <<"htm">> := <<"POST">>,
                <<"htu">> := Endpoint,
                <<"iat">> := _,
                <<"exp">> := _,
                <<"ath">> := AccessTokenHash,
                <<"nonce">> := <<"dpop_nonce">>
            }
        },
        DpopJwtWithNonce
    ),
    ok.

trusted_audiences_test() ->
    ClientContext =
        #oidcc_client_context{
            client_id = ClientId,
            jwks = Jwk,
            provider_configuration = #oidcc_provider_configuration{issuer = Issuer}
        } = client_context_fapi2_fixture(),

    ExtraAudience = <<"audience_member">>,
    LocalEndpoint = <<"https://my.server/auth">>,
    AuthCode = <<"1234567890">>,
    AccessToken = <<"access_token">>,
    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => [ClientId, ExtraAudience],
            <<"azp">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10
        },

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),

    TokenData =
        jsx:encode(#{
            <<"access_token">> => AccessToken,
            <<"token_type">> => <<"Bearer">>,
            <<"id_token">> => Token,
            <<"scope">> => <<"profile openid">>
        }),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {_TokenEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], TokenData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {ok, #oidcc_token{}},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint}
        )
    ),

    ?assertMatch(
        {ok, #oidcc_token{}},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint, trusted_audiences => any}
        )
    ),

    ?assertMatch(
        {ok, #oidcc_token{}},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint, trusted_audiences => [ExtraAudience]}
        )
    ),

    ?assertMatch(
        {error, {missing_claim, {<<"aud">>, ClientId}, Claims}},
        oidcc_token:retrieve(
            AuthCode,
            ClientContext,
            #{redirect_uri => LocalEndpoint, trusted_audiences => []}
        )
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

retrieve_pkce_test() ->
    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {_TokenEndpoint, _Header, "application/x-www-form-urlencoded", _Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            {ok, {{"HTTP/1.1", 500, "Server Error"}, [], "SUCCESS"}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    PkceSupportedClientContext = client_context_fapi2_fixture(),
    PkceUnsupportedClientContext = PkceSupportedClientContext#oidcc_client_context{
        provider_configuration = PkceSupportedClientContext#oidcc_client_context.provider_configuration#oidcc_provider_configuration{
            code_challenge_methods_supported = undefined
        }
    },
    RedirectUri = <<"https://redirect.example/">>,

    ?assertEqual(
        {error, pkce_verifier_required},
        oidcc_token:retrieve(<<"code">>, PkceSupportedClientContext, #{
            redirect_uri => RedirectUri,
            require_pkce => true
        })
    ),

    ?assertEqual(
        {error, {http_error, 500, "SUCCESS"}},
        oidcc_token:retrieve(<<"code">>, PkceSupportedClientContext, #{
            redirect_uri => RedirectUri,
            require_pkce => true,
            pkce_verifier => <<"verifier">>
        })
    ),

    ?assertEqual(
        {error, no_supported_code_challenge},
        oidcc_token:retrieve(<<"code">>, PkceUnsupportedClientContext, #{
            redirect_uri => RedirectUri,
            require_pkce => true,
            pkce_verifier => <<"verifier">>
        })
    ),

    ?assertEqual(
        {error, {http_error, 500, "SUCCESS"}},
        oidcc_token:retrieve(<<"code">>, PkceUnsupportedClientContext, #{
            redirect_uri => RedirectUri,
            pkce_verifier => <<"verifier">>
        })
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

validate_jarm_test() ->
    ClientContext0 = client_context_fapi2_fixture(),
    #oidcc_client_context{
        client_id = ClientId,
        jwks = Jwk,
        provider_configuration =
            #oidcc_provider_configuration{
                issuer = Issuer
            }
    } = ClientContext0,
    EncAlgValue = <<"RSA-OAEP-256">>,
    EncEncValue = <<"A256GCM">>,
    EncJwk0 = jose_jwk:generate_key({rsa, 2048}),
    EncJwk = EncJwk0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},
    ClientContext = ClientContext0#oidcc_client_context{
        jwks = oidcc_jwt_util:merge_jwks(Jwk, EncJwk)
    },
    Jws = #{<<"alg">> => <<"RS256">>},
    AuthCode = <<"123456">>,
    JarmClaims = #{
        <<"iss">> => Issuer,
        <<"aud">> => ClientId,
        <<"code">> => AuthCode,
        <<"exp">> => erlang:system_time(second) + 10
    },
    {_, JarmToken0} = jose_jws:compact(
        jose_jwt:sign(Jwk, Jws, JarmClaims)
    ),
    {_, JarmToken} = jose_jwe:compact(
        jose_jwk:block_encrypt(
            JarmToken0,
            jose_jwe:from_map(#{<<"alg">> => EncAlgValue, <<"enc">> => EncEncValue}),
            EncJwk
        )
    ),

    ?assertEqual(
        {ok, JarmClaims},
        oidcc_token:validate_jarm(
            JarmToken,
            ClientContext,
            #{}
        )
    ),

    ok.

validate_jarm_invalid_token_test() ->
    ClientContext = client_context_fapi2_fixture(),
    #oidcc_client_context{
        client_id = ClientId,
        jwks = Jwk,
        provider_configuration =
            #oidcc_provider_configuration{
                issuer = Issuer
            }
    } = ClientContext,

    Jws = #{<<"alg">> => <<"RS256">>},
    RedirectUri = <<"https://redirect.example/">>,
    JarmClaims = #{
        <<"iss">> => Issuer,
        <<"aud">> => ClientId,
        <<"code">> => <<"123456">>,
        <<"exp">> => erlang:system_time(second) + 10
    },
    JarmClaimsInvalidIssuer = JarmClaims#{
        <<"iss">> => <<"invalid">>
    },
    JarmClaimsExtraAudience = JarmClaims#{
        <<"aud">> => [ClientId, <<"extra">>]
    },
    JarmClaimsExpired = JarmClaims#{
        <<"exp">> => erlang:system_time(second) - 10
    },
    JarmClaimsNotYetValid = JarmClaims#{
        <<"nbf">> => erlang:system_time(second) + 10
    },
    {_, JarmTokenInvalidIssuer} = jose_jws:compact(
        jose_jwt:sign(Jwk, Jws, jose_jwt:from(JarmClaimsInvalidIssuer))
    ),
    {_, JarmTokenExtraAudience} = jose_jws:compact(
        jose_jwt:sign(Jwk, Jws, jose_jwt:from(JarmClaimsExtraAudience))
    ),
    {_, JarmTokenExpired} = jose_jws:compact(
        jose_jwt:sign(Jwk, Jws, jose_jwt:from(JarmClaimsExpired))
    ),
    {_, JarmTokenNotYetValid} = jose_jws:compact(
        jose_jwt:sign(Jwk, Jws, jose_jwt:from(JarmClaimsNotYetValid))
    ),
    {_, JarmTokenWrongSignature} = jose_jws:compact(
        jose_jwt:sign(jose_jwk:generate_key({rsa, 2048}), Jws, jose_jwt:from(JarmClaims))
    ),
    {_, JarmTokenWrongSignatureInvalidIssuer} = jose_jws:compact(
        jose_jwt:sign(
            jose_jwk:generate_key({rsa, 2048}), Jws, jose_jwt:from(JarmClaimsInvalidIssuer)
        )
    ),

    ?assertMatch(
        {error, {missing_claim, {<<"iss">>, Issuer}, JarmClaimsInvalidIssuer}},
        oidcc_token:validate_jarm(
            JarmTokenInvalidIssuer,
            ClientContext,
            #{}
        )
    ),

    ?assertMatch(
        {error, no_matching_key},
        oidcc_token:validate_jarm(
            JarmTokenWrongSignatureInvalidIssuer,
            ClientContext,
            #{}
        )
    ),

    ?assertMatch(
        {error, {missing_claim, {<<"aud">>, ClientId}, JarmClaimsExtraAudience}},
        oidcc_token:validate_jarm(
            JarmTokenExtraAudience,
            ClientContext,
            #{trusted_audiences => []}
        )
    ),

    ?assertMatch(
        {ok, #{}},
        oidcc_token:validate_jarm(
            JarmTokenExtraAudience,
            ClientContext,
            #{trusted_audiences => any}
        )
    ),

    ?assertMatch(
        {ok, #{}},
        oidcc_token:validate_jarm(
            JarmTokenExtraAudience,
            ClientContext,
            #{trusted_audiences => [<<"extra">>]}
        )
    ),

    ?assertMatch(
        {error, {missing_claim, {<<"aud">>, ClientId}, JarmClaimsExtraAudience}},
        oidcc_token:validate_jarm(
            JarmTokenExtraAudience,
            ClientContext,
            #{trusted_audiences => [<<"not_extra">>]}
        )
    ),

    ?assertMatch(
        {error, token_expired},
        oidcc_token:validate_jarm(
            JarmTokenExpired,
            ClientContext,
            #{}
        )
    ),

    ?assertMatch(
        {error, token_not_yet_valid},
        oidcc_token:validate_jarm(
            JarmTokenNotYetValid,
            ClientContext,
            #{redirect_uri => RedirectUri}
        )
    ),

    ?assertMatch(
        {error, no_matching_key},
        oidcc_token:validate_jarm(
            JarmTokenWrongSignature,
            ClientContext,
            #{redirect_uri => RedirectUri}
        )
    ),

    ok.

validate_id_token_encrypted_token_test() ->
    #oidcc_client_context{client_id = ClientId, jwks = Jwk, provider_configuration = Configuration0} =
        ClientContext0 = client_context_fapi2_fixture(),

    #oidcc_provider_configuration{issuer = Issuer} =
        Configuration = Configuration0#oidcc_provider_configuration{
            token_endpoint_auth_methods_supported = [<<"private_key_jwt">>],
            token_endpoint_auth_signing_alg_values_supported = [<<"RS256">>],
            id_token_encryption_alg_values_supported = [<<"RSA-OAEP">>],
            id_token_encryption_enc_values_supported = [<<"A256GCM">>]
        },

    ClientContext = ClientContext0#oidcc_client_context{provider_configuration = Configuration},

    Claims =
        #{
            <<"iss">> => Issuer,
            <<"sub">> => <<"sub">>,
            <<"aud">> => ClientId,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10,
            <<"at_hash">> => <<"hrOQHuo3oE6FR82RIiX1SA">>
        },

    Jwt = jose_jwt:from(Claims),
    Jws = #{<<"alg">> => <<"RS256">>},
    {_Jws, Token0} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, Jwt)
        ),
    Jwe = #{<<"alg">> => <<"RSA-OAEP">>, <<"enc">> => <<"A256GCM">>},
    {_Jwe, Token} =
        jose_jwe:compact(jose_jwk:block_encrypt(Token0, Jwe, Jwk)),

    ?assertEqual(
        {ok, Claims},
        oidcc_token:validate_id_token(Token, ClientContext, #{})
    ),

    ok.

validate_jwt_test() ->
    #oidcc_client_context{
        client_id = ClientId,
        jwks = Jwk,
        provider_configuration = #oidcc_provider_configuration{issuer = Issuer}
    } =
        ClientContext = client_context_fapi2_fixture(),

    GoodClaims =
        #{
            <<"iss">> => Issuer,
            <<"aud">> => ClientId,
            <<"sub">> => <<"1234">>,
            <<"iat">> => erlang:system_time(second),
            <<"exp">> => erlang:system_time(second) + 10
        },
    Expired = GoodClaims#{<<"exp">> => erlang:system_time(second) - 1},
    NotYetValid = GoodClaims#{<<"nbf">> => erlang:system_time(second) + 5},
    WrongIssuer = GoodClaims#{<<"iss">> => <<"wrong">>},
    WrongAudience = GoodClaims#{<<"aud">> => <<"wrong">>},

    JwtFun = fun(Claims) ->
        Jwt = jose_jwt:from(Claims),
        Jws = #{<<"alg">> => <<"RS256">>},
        {_Jws, Token} =
            jose_jws:compact(
                jose_jwt:sign(Jwk, Jws, Jwt)
            ),
        Token
    end,

    Opts = #{
        signing_algs => [<<"RS256">>]
    },

    ?assertEqual(
        {ok, GoodClaims},
        oidcc_token:validate_jwt(JwtFun(GoodClaims), ClientContext, Opts)
    ),

    ?assertEqual(
        {error, token_expired},
        oidcc_token:validate_jwt(JwtFun(Expired), ClientContext, Opts)
    ),

    ?assertEqual(
        {error, token_not_yet_valid},
        oidcc_token:validate_jwt(JwtFun(NotYetValid), ClientContext, Opts)
    ),

    ?assertEqual(
        {error, {missing_claim, {<<"iss">>, Issuer}, WrongIssuer}},
        oidcc_token:validate_jwt(JwtFun(WrongIssuer), ClientContext, Opts)
    ),

    ?assertEqual(
        {error, {missing_claim, {<<"aud">>, ClientId}, WrongAudience}},
        oidcc_token:validate_jwt(JwtFun(WrongAudience), ClientContext, Opts)
    ),

    ?assertEqual(
        {error, no_matching_key},
        oidcc_token:validate_jwt(JwtFun(WrongAudience), ClientContext, #{})
    ),

    ok.

client_context_fapi2_fixture() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/fapi2-metadata.json"),
    {ok, Configuration} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ConfigurationBinary)
    ),

    Jwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwk = Jwk0#jose_jwk{fields = #{<<"use">> => <<"sig">>}},
    ClientJwk0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = ClientJwk0#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>}
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    oidcc_client_context:from_manual(Configuration, Jwk, ClientId, ClientSecret, #{
        client_jwks => ClientJwk
    }).
