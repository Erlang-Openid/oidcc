%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_userinfo_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

json_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    HttpBody = <<"{\"name\":\"joe\", \"sub\":\"123456\"}">>,
    GoodSub = <<"123456">>,
    BadSub = <<"123789">>,

    HttpFun =
        fun(get, {Url, _Header}, _HttpOpts, _Opts, _Profile) ->
            Url = UserInfoEndpoint,
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], HttpBody}}
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    AccessToken = <<"opensesame">>,
    GoodToken =
        #oidcc_token{
            access = AccessTokenRecord = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },
    BadToken =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123457">>}
                }
        },

    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(GoodToken, ClientContext, #{})
    ),
    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(AccessTokenRecord, ClientContext, #{
            expected_subject => GoodSub
        })
    ),
    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => GoodSub}
        )
    ),

    ?assertMatch(
        {error, bad_subject},
        oidcc_userinfo:retrieve(BadToken, ClientContext, #{})
    ),
    ?assertMatch(
        {error, bad_subject},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => BadSub}
        )
    ),
    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => any}
        )
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

jwt_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint, issuer = Issuer} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    JwkBeforeRefresh0 = jose_jwk:generate_key(16),
    JwkBeforeRefresh = JwkBeforeRefresh0#jose_jwk{fields = #{<<"kid">> => <<"kid1">>}},

    JwkAfterRefresh0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    JwkAfterRefresh = JwkAfterRefresh0#jose_jwk{fields = #{<<"kid">> => <<"kid2">>}},

    RefreshJwksFun = fun(_OldJwk, <<"kid2">>) -> {ok, JwkAfterRefresh} end,

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, JwkBeforeRefresh, ClientId, ClientSecret
    ),

    GoodSub = <<"123456">>,
    BadSub = <<"123789">>,

    UserinfoJwt = jose_jwt:from_map(#{
        <<"iss">> => Issuer,
        <<"name">> => <<"joe">>,
        <<"sub">> => <<"123456">>,
        <<"aud">> => ClientId,
        <<"iat">> => erlang:system_time(second),
        <<"exp">> => erlang:system_time(second) + 10
    }),
    UserinfoJws = #{<<"alg">> => <<"RS256">>, <<"kid">> => <<"kid2">>},

    {_Jws, HttpBody} =
        jose_jws:compact(
            jose_jwt:sign(JwkAfterRefresh, UserinfoJws, UserinfoJwt)
        ),

    HttpFun =
        fun(get, {Url, _Header}, _HttpOpts, _Opts, _Profile) ->
            Url = UserInfoEndpoint,
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/jwt"}], HttpBody}}
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    AccessToken = <<"opensesame">>,
    GoodToken =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },
    BadToken =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123457">>}
                }
        },

    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(GoodToken, ClientContext, #{refresh_jwks => RefreshJwksFun})
    ),
    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => GoodSub, refresh_jwks => RefreshJwksFun}
        )
    ),

    ?assertMatch(
        {error, {missing_claim, {<<"sub">>, _}, _}},
        oidcc_userinfo:retrieve(BadToken, ClientContext, #{refresh_jwks => RefreshJwksFun})
    ),
    ?assertMatch(
        {error, {missing_claim, {<<"sub">>, _}, _}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => BadSub, refresh_jwks => RefreshJwksFun}
        )
    ),
    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => any, refresh_jwks => RefreshJwksFun}
        )
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

jwt_encrypted_not_signed_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwk = jose_jwk:generate_key({rsa, 1024}),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwk, ClientId, ClientSecret
    ),

    Sub = <<"123456">>,

    %% iss and aud claims are only required if the token is signed; not encrypted.
    %% https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.3.2
    %%  If signed, the UserInfo Response MUST contain the Claims iss (issuer)
    %%  and aud (audience) as members. The iss value MUST be the OP's Issuer
    %%  Identifier URL. The aud value MUST be or include the RP's Client ID
    %%  value.
    {_, UserinfoJwt} = jose_jwt:to_binary(#{
        <<"name">> => <<"joe">>,
        <<"sub">> => Sub,
        <<"iat">> => erlang:system_time(second),
        <<"exp">> => erlang:system_time(second) + 10
    }),
    UserinfoJwe = #{<<"alg">> => <<"RSA-OAEP">>, <<"enc">> => <<"A256GCM">>},

    {_Jwe, HttpBody} =
        jose_jwe:compact(
            jose_jwk:block_encrypt(UserinfoJwt, UserinfoJwe, Jwk)
        ),

    HttpFun =
        fun(get, {_Url, _Header}, _HttpOpts, _Opts, _Profile) ->
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/jwt"}], HttpBody}}
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    AccessToken = <<"opensesame">>,
    Token =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => Sub}
                }
        },

    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

distributed_claims_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorithm for test
    jose:unsecured_signing(true),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    Sub = <<"123456">>,

    Jwk = jose_jwk:generate_key(16),
    Jws = #{<<"alg">> => <<"none">>},

    LocalClaims = #{<<"last_name">> => <<"Armstrong">>},
    LocalJwt = jose_jwt:from(LocalClaims),
    {_, LocalToken} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, LocalJwt)
        ),

    RemoteClaims = #{<<"first_name">> => <<"Joe">>},
    RemoteJwt = jose_jwt:from(RemoteClaims),
    {_, RemoteToken} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, RemoteJwt)
        ),

    HttpFun =
        fun(get, {Url, _Header}, _TelemetryOpts, _RequestOpts) ->
            case Url of
                UserInfoEndpoint ->
                    {ok,
                        {
                            {json, #{
                                <<"sub">> => Sub,
                                <<"_claim_names">> => #{
                                    <<"first_name">> => <<"remote">>,
                                    <<"last_name">> => <<"local">>
                                },
                                <<"_claim_sources">> => #{
                                    <<"remote">> => #{
                                        <<"endpoint">> =>
                                            <<"https://my.provider/distributed-claim">>,
                                        <<"access_token">> => <<"acces_token">>
                                    },
                                    <<"local">> => #{
                                        <<"JWT">> => LocalToken
                                    }
                                }
                            }},
                            []
                        }};
                <<"https://my.provider/distributed-claim">> ->
                    {ok, {{jwt, RemoteToken}, []}}
            end
        end,
    ok = meck:new(oidcc_http_util, [passthrough]),
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    AccessToken = <<"opensesame">>,
    Token =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },

    ?assertMatch(
        {ok, #{<<"first_name">> := <<"Joe">>, <<"last_name">> := <<"Armstrong">>}},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),
    ?assertMatch(
        {ok, #{<<"first_name">> := <<"Joe">>, <<"last_name">> := <<"Armstrong">>}},
        oidcc_userinfo:retrieve(
            AccessToken,
            ClientContext,
            #{expected_subject => Sub}
        )
    ),

    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_http_util),

    ok.

distributed_claims_invalid_json_resp_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorithm for test
    jose:unsecured_signing(true),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    Sub = <<"123456">>,

    Jwk = jose_jwk:generate_key(16),
    Jws = #{<<"alg">> => <<"none">>},

    LocalClaims = #{<<"last_name">> => <<"Armstrong">>},
    LocalJwt = jose_jwt:from(LocalClaims),
    {_, LocalToken} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, LocalJwt)
        ),

    HttpFun =
        fun(get, {Url, _Header}, _TelemetryOpts, _RequestOpts) ->
            case Url of
                UserInfoEndpoint ->
                    {ok,
                        {
                            {json, #{
                                <<"sub">> => Sub,
                                <<"_claim_names">> => #{
                                    <<"first_name">> => <<"remote">>,
                                    <<"last_name">> => <<"local">>
                                },
                                <<"_claim_sources">> => #{
                                    <<"remote">> => #{
                                        <<"endpoint">> =>
                                            <<"https://my.provider/distributed-claim">>,
                                        <<"access_token">> => <<"acces_token">>
                                    },
                                    <<"local">> => #{
                                        <<"JWT">> => LocalToken
                                    }
                                }
                            }},
                            []
                        }};
                <<"https://my.provider/distributed-claim">> ->
                    {ok, {{json, #{<<"first_name">> => <<"Joe">>}}, []}}
            end
        end,
    ok = meck:new(oidcc_http_util, [passthrough]),
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    AccessToken = <<"opensesame">>,
    Token =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },

    ?assertMatch(
        {error, invalid_content_type},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_http_util),

    ok.

distributed_claims_http_error_resp_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorithm for test
    jose:unsecured_signing(true),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    Sub = <<"123456">>,

    Jwk = jose_jwk:generate_key(16),
    Jws = #{<<"alg">> => <<"none">>},

    LocalClaims = #{<<"last_name">> => <<"Armstrong">>},
    LocalJwt = jose_jwt:from(LocalClaims),
    {_, LocalToken} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, LocalJwt)
        ),

    HttpFun =
        fun(get, {Url, _Header}, _TelemetryOpts, _RequestOpts) ->
            case Url of
                UserInfoEndpoint ->
                    {ok,
                        {
                            {json, #{
                                <<"sub">> => Sub,
                                <<"_claim_names">> => #{
                                    <<"first_name">> => <<"remote">>,
                                    <<"last_name">> => <<"local">>
                                },
                                <<"_claim_sources">> => #{
                                    <<"remote">> => #{
                                        <<"endpoint">> =>
                                            <<"https://my.provider/distributed-claim">>,
                                        <<"access_token">> => <<"acces_token">>
                                    },
                                    <<"local">> => #{
                                        <<"JWT">> => LocalToken
                                    }
                                }
                            }},
                            []
                        }};
                <<"https://my.provider/distributed-claim">> ->
                    {error, some_error}
            end
        end,
    ok = meck:new(oidcc_http_util, [passthrough]),
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    AccessToken = <<"opensesame">>,
    Token =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },

    ?assertMatch(
        {error, some_error},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_http_util),

    ok.

distributed_claims_invalid_source_mapping_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorithm for test
    jose:unsecured_signing(true),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    Sub = <<"123456">>,

    Jwk = jose_jwk:generate_key(16),
    Jws = #{<<"alg">> => <<"none">>},

    LocalClaims = #{<<"last_name">> => <<"Armstrong">>},
    LocalJwt = jose_jwt:from(LocalClaims),
    {_, LocalToken} =
        jose_jws:compact(
            jose_jwt:sign(Jwk, Jws, LocalJwt)
        ),

    HttpFun =
        fun(get, {Url, _Header}, _TelemetryOpts, _RequestOpts) ->
            UserInfoEndpoint = Url,

            {ok,
                {
                    {json, #{
                        <<"sub">> => Sub,
                        <<"_claim_names">> => #{
                            <<"first_name">> => <<"remote">>,
                            <<"last_name">> => <<"remote">>
                        },
                        <<"_claim_sources">> => #{
                            <<"local">> => #{
                                <<"JWT">> => LocalToken
                            }
                        }
                    }},
                    []
                }}
        end,
    ok = meck:new(oidcc_http_util, [passthrough]),
    ok = meck:expect(oidcc_http_util, request, HttpFun),

    AccessToken = <<"opensesame">>,
    Token =
        #oidcc_token{
            access = #oidcc_token_access{token = AccessToken},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => <<"123456">>}
                }
        },

    ?assertMatch(
        {error, {distributed_claim_not_found, {<<"remote">>, <<"first_name">>}}},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    true = meck:validate(oidcc_http_util),
    meck:unload(oidcc_http_util),

    ok.

dpop_proof_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration0} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Configuration = Configuration0#oidcc_provider_configuration{
        dpop_signing_alg_values_supported = [<<"RS256">>]
    },
    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwk = Jwks#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientJwks = #jose_jwk{keys = {jose_jwk_set, [ClientJwk]}},

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwks, ClientId, ClientSecret, #{client_jwks => ClientJwks}
    ),

    HttpBody = <<"{\"name\":\"joe\", \"sub\":\"123456\"}">>,
    Sub = <<"123456">>,
    AccessToken = <<"opensesame">>,
    AccessTokenHash = base64:encode(
        crypto:hash(sha256, AccessToken),
        #{mode => urlsafe, padding => false}
    ),

    HttpFun =
        fun(get, {Url, Header}, _HttpOpts, _Opts, _Profile) ->
            Url = UserInfoEndpoint,
            {_, Authorization} =
                proplists:lookup("authorization", Header),
            ?assertEqual(
                list_to_binary(Authorization),
                list_to_binary([<<"DPoP ">>, AccessToken])
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
                        <<"htm">> := <<"GET">>,
                        <<"htu">> := UserInfoEndpoint,
                        <<"ath">> := AccessTokenHash
                    }
                },
                DpopJwt
            ),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], HttpBody}}
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    Token =
        #oidcc_token{
            access =
                #oidcc_token_access{token = AccessToken, type = <<"DPoP">>},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => Sub}
                }
        },

    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

dpop_proof_case_insensitive_token_type_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration0} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Configuration = Configuration0#oidcc_provider_configuration{
        dpop_signing_alg_values_supported = [<<"RS256">>]
    },
    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientJwk = Jwks#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwks, ClientId, ClientSecret, #{client_jwks => ClientJwk}
    ),

    HttpBody = <<"{\"name\":\"joe\", \"sub\":\"123456\"}">>,
    Sub = <<"123456">>,
    AccessToken = <<"opensesame">>,

    HttpFun =
        fun(get, {Url, Header}, _HttpOpts, _Opts, _Profile) ->
            Url = UserInfoEndpoint,
            {_, Authorization} =
                proplists:lookup("authorization", Header),
            ?assertEqual(
                list_to_binary(Authorization),
                list_to_binary([<<"dpOp ">>, AccessToken])
            ),
            ?assertMatch({_, _}, proplists:lookup("dpop", Header)),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], HttpBody}}
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    Token =
        #oidcc_token{
            access =
                #oidcc_token_access{token = AccessToken, type = <<"dpOp">>},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => Sub}
                }
        },

    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

dpop_proof_with_nonce_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{userinfo_endpoint = UserInfoEndpoint} = Configuration0} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Configuration = Configuration0#oidcc_provider_configuration{
        dpop_signing_alg_values_supported = [<<"RS256">>]
    },
    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientJwk = Jwks#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwks, ClientId, ClientSecret, #{client_jwks => ClientJwk}
    ),

    HttpBody = <<"{\"name\":\"joe\", \"sub\":\"123456\"}">>,
    Sub = <<"123456">>,
    AccessToken = <<"opensesame">>,
    AccessTokenHash = base64:encode(
        crypto:hash(sha256, AccessToken),
        #{mode => urlsafe, padding => false}
    ),
    DpopNonce = <<"dpop_nonce">>,
    DpopNonceError = jsx:encode(#{
        <<"error">> => <<"use_dpop_nonce">>,
        <<"error_description">> =>
            <<"Authorization server requires nonce in DPoP proof">>
    }),

    HttpFun =
        fun(get, {Url, Header}, _HttpOpts, _Opts, _Profile) ->
            Url = UserInfoEndpoint,
            {_, Authorization} =
                proplists:lookup("authorization", Header),
            ?assertEqual(
                list_to_binary(Authorization),
                list_to_binary([<<"DPoP ">>, AccessToken])
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
                        <<"htm">> := <<"GET">>,
                        <<"htu">> := UserInfoEndpoint,
                        <<"ath">> := AccessTokenHash
                    }
                },
                DpopJwt
            ),

            case DpopJwt of
                #jose_jwt{fields = #{<<"nonce">> := DpopNonce}} ->
                    {ok, {
                        {"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], HttpBody
                    }};
                _ ->
                    {ok, {
                        {"HTTP/1.1", 400, "Bad Request"},
                        [
                            {"content-type", "application/json"},
                            {"dpop-nonce", binary_to_list(DpopNonce)}
                        ],
                        DpopNonceError
                    }}
            end
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    Token =
        #oidcc_token{
            access =
                #oidcc_token_access{token = AccessToken, type = <<"DPoP">>},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => Sub}
                }
        },

    ?assertMatch(
        {ok, #{<<"name">> := <<"joe">>}},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

dpop_proof_with_invalid_nonce_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Configuration = Configuration0#oidcc_provider_configuration{
        dpop_signing_alg_values_supported = [<<"RS256">>]
    },
    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientJwk = Jwks#jose_jwk{
        fields = #{<<"kid">> => <<"private_kid">>, <<"use">> => <<"sig">>}
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwks, ClientId, ClientSecret, #{client_jwks => ClientJwk}
    ),

    Sub = <<"123456">>,
    AccessToken = <<"opensesame">>,
    DpopNonce = <<"dpop_nonce">>,
    DpopNonceError = jsx:encode(#{
        <<"error">> => <<"use_dpop_nonce">>,
        <<"error_description">> =>
            <<"Authorization server requires nonce in DPoP proof">>
    }),

    HttpFun =
        fun(get, _UrlHeader, _HttpOpts, _Opts, _Profile) ->
            {ok, {
                {"HTTP/1.1", 400, "Bad Request"},
                [{"content-type", "application/json"}, {"dpop-nonce", binary_to_list(DpopNonce)}],
                DpopNonceError
            }}
        end,
    ok = meck:new(httpc),
    ok = meck:expect(httpc, request, HttpFun),

    Token =
        #oidcc_token{
            access =
                #oidcc_token_access{token = AccessToken, type = <<"DPoP">>},
            id =
                #oidcc_token_id{
                    token = "id_token",
                    claims = #{<<"sub">> => Sub}
                }
        },

    ?assertMatch(
        {error, _},
        oidcc_userinfo:retrieve(Token, ClientContext, #{dpop_nonce => <<"invalid_nonce">>})
    ),

    true = meck:validate(httpc),
    meck:unload(httpc),

    ok.

retrieve_no_access_token_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    ClientContext = oidcc_client_context:from_manual(
        Configuration, Jwks, ClientId, ClientSecret
    ),

    Token = #oidcc_token{
        access = none,
        id = #oidcc_token_id{}
    },

    ?assertMatch(
        {error, no_access_token},
        oidcc_userinfo:retrieve(Token, ClientContext, #{})
    ),

    ok.
