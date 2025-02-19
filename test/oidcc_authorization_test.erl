%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_authorization_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwe.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

create_redirect_url_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),
    PkcePlainConfiguration = Configuration#oidcc_provider_configuration{
        code_challenge_methods_supported = [<<"plain">>]
    },
    NoPkceConfiguration = Configuration#oidcc_provider_configuration{
        code_challenge_methods_supported = undefined
    },

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,
    State = <<"someimportantstate">>,
    Nonce = <<"noncenonce">>,
    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, <<"client_secret">>),
    PkcePlainClientContext =
        oidcc_client_context:from_manual(
            PkcePlainConfiguration, Jwks, ClientId, <<"client_secret">>
        ),
    NoPkceClientContext =
        oidcc_client_context:from_manual(NoPkceConfiguration, Jwks, ClientId, <<"client_secret">>),

    BaseOpts =
        #{
            redirect_uri => RedirectUri,
            client_id => ClientId,
            url_extension => [{<<"test">>, <<"id">>}]
        },
    Opts1 = maps:merge(BaseOpts, #{scopes => ["email", <<"openid">>, profile]}),
    Opts2 = maps:merge(BaseOpts, #{scopes => ["email", <<"profile">>], state => State}),
    Opts3 =
        maps:merge(
            BaseOpts,
            #{
                scopes => [email, profile, openid],
                state => State,
                nonce => Nonce
            }
        ),
    Opts4 =
        maps:merge(
            BaseOpts,
            #{
                scopes => ["email", <<"openid">>],
                url_extension => [{<<"test">>, <<"id">>}, {<<"other">>, <<"green">>}]
            }
        ),
    Opts5 = maps:merge(BaseOpts, #{pkce_verifier => <<"foo">>}),
    Opts6 = maps:merge(Opts5, #{require_pkce => true}),
    Opts7 = maps:merge(BaseOpts, #{require_pkce => true}),
    Opts8 = maps:merge(BaseOpts, #{purpose => <<"purpose">>}),
    Opts9 = maps:merge(Opts8, #{purpose_required => true}),
    Opts10 = maps:merge(BaseOpts, #{purpose_required => true}),

    {ok, Url1} = oidcc_authorization:create_redirect_url(ClientContext, BaseOpts),
    {ok, Url2} = oidcc_authorization:create_redirect_url(ClientContext, Opts1),
    {ok, Url3} = oidcc_authorization:create_redirect_url(ClientContext, Opts2),
    {ok, Url4} = oidcc_authorization:create_redirect_url(ClientContext, Opts3),
    {ok, Url5} = oidcc_authorization:create_redirect_url(ClientContext, Opts4),
    {ok, Url6} = oidcc_authorization:create_redirect_url(ClientContext, Opts5),
    {ok, Url7} = oidcc_authorization:create_redirect_url(PkcePlainClientContext, Opts5),
    {ok, Url8} = oidcc_authorization:create_redirect_url(NoPkceClientContext, Opts5),
    {ok, Url9} = oidcc_authorization:create_redirect_url(PkcePlainClientContext, Opts6),
    {ok, Url10} = oidcc_authorization:create_redirect_url(ClientContext, Opts8),
    {ok, Url11} = oidcc_authorization:create_redirect_url(ClientContext, Opts9),

    ExpUrl1 =
        <<"https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl1, iolist_to_binary(Url1)),

    ExpUrl2 =
        <<"https://my.provider/auth?scope=email+openid+profile&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl2, iolist_to_binary(Url2)),

    ExpUrl3 =
        <<"https://my.provider/auth?scope=email+profile&state=someimportantstate&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl3, iolist_to_binary(Url3)),

    ExpUrl4 =
        <<"https://my.provider/auth?scope=email+profile+openid&nonce=noncenonce&state=someimportantstate&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl4, iolist_to_binary(Url4)),

    ExpUrl5 =
        <<"https://my.provider/auth?scope=email+openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id&other=green">>,
    ?assertEqual(ExpUrl5, iolist_to_binary(Url5)),

    ExpUrl6 =
        <<"https://my.provider/auth?scope=openid&code_challenge=LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564&code_challenge_method=S256&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl6, iolist_to_binary(Url6)),

    ExpUrl7 =
        <<"https://my.provider/auth?scope=openid&code_challenge=foo&code_challenge_method=plain&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl7, iolist_to_binary(Url7)),

    ExpUrl8 =
        <<"https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl8, iolist_to_binary(Url8)),

    ?assertEqual(iolist_to_binary(Url9), iolist_to_binary(Url7)),

    ExpUrl10 =
        <<"https://my.provider/auth?scope=openid&purpose=purpose&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn&test=id">>,
    ?assertEqual(ExpUrl10, iolist_to_binary(Url10)),

    ?assertEqual(iolist_to_binary(Url11), iolist_to_binary(Url10)),

    ?assertEqual(
        {error, no_supported_code_challenge},
        oidcc_authorization:create_redirect_url(NoPkceClientContext, Opts6)
    ),

    ?assertEqual(
        {error, pkce_verifier_required},
        oidcc_authorization:create_redirect_url(ClientContext, Opts7)
    ),

    ?assertEqual(
        {error, purpose_required},
        oidcc_authorization:create_redirect_url(ClientContext, Opts10)
    ),

    ok.

create_redirect_url_with_request_object_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{issuer = Issuer} = Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"none">>,
            <<"HS256">>,
            <<"RS256">>,
            <<"PS256">>,
            <<"ES256">>,
            <<"EdDSA">>
        ],
        request_object_encryption_alg_values_supported = [
            <<"RSA1_5">>,
            <<"RSA-OAEP">>,
            <<"RSA-OAEP-256">>,
            <<"RSA-OAEP-384">>,
            <<"RSA-OAEP-512">>,
            <<"ECDH-ES">>,
            <<"ECDH-ES+A128KW">>,
            <<"ECDH-ES+A192KW">>,
            <<"ECDH-ES+A256KW">>,
            <<"A128KW">>,
            <<"A192KW">>,
            <<"A256KW">>,
            <<"A128GCMKW">>,
            <<"A192GCMKW">>,
            <<"A256GCMKW">>,
            <<"dir">>
        ],
        request_object_encryption_enc_values_supported = [
            <<"A128CBC-HS256">>,
            <<"A192CBC-HS384">>,
            <<"A256CBC-HS512">>,
            <<"A128GCM">>,
            <<"A192GCM">>,
            <<"A256GCM">>
        ]
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri,
        url_extension => [{<<"should_be_in">>, <<"both">>}]
    }),

    ?assertMatch(<<"https://my.provider/auth?request=", _/binary>>, iolist_to_binary(Url)),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    ?assertMatch(
        #{
            <<"client_id">> := <<"client_id">>,
            <<"response_type">> := <<"code">>,
            <<"scope">> := <<"openid">>,
            <<"should_be_in">> := <<"both">>,
            <<"request">> := _
        },
        QueryParams
    ),

    {SignedToken, Jwe} = jose_jwe:block_decrypt(Jwks, maps:get(<<"request">>, QueryParams)),

    ?assertMatch(#jose_jwe{alg = {jose_jwe_alg_rsa, _}}, Jwe),

    {true, Jwt, Jws} = jose_jwt:verify(jose_jwk:from_oct(ClientSecret), SignedToken),

    ?assertMatch(#jose_jws{alg = {jose_jws_alg_hmac, 'HS256'}}, Jws),

    ?assertMatch(
        #jose_jwt{
            fields = #{
                <<"aud">> := Issuer,
                <<"client_id">> := ClientId,
                <<"exp">> := _,
                <<"iat">> := _,
                <<"iss">> := ClientId,
                <<"jti">> := _,
                <<"nbf">> := _,
                <<"redirect_uri">> := RedirectUri,
                <<"response_type">> := <<"code">>,
                <<"scope">> := <<"openid">>,
                <<"should_be_in">> := <<"both">>
            }
        },
        Jwt
    ),

    ok.

create_redirect_url_with_request_object_and_max_clock_skew_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{} = Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"none">>,
            <<"PS256">>,
            <<"HS256">>,
            <<"RS256">>,
            <<"ES256">>,
            <<"EdDSA">>
        ],
        request_object_encryption_alg_values_supported = [
            <<"RSA1_5">>,
            <<"RSA-OAEP">>,
            <<"RSA-OAEP-256">>,
            <<"RSA-OAEP-384">>,
            <<"RSA-OAEP-512">>,
            <<"ECDH-ES">>,
            <<"ECDH-ES+A128KW">>,
            <<"ECDH-ES+A192KW">>,
            <<"ECDH-ES+A256KW">>,
            <<"A128KW">>,
            <<"A192KW">>,
            <<"A256KW">>,
            <<"A128GCMKW">>,
            <<"A192GCMKW">>,
            <<"A256GCMKW">>,
            <<"dir">>
        ],
        request_object_encryption_enc_values_supported = [
            <<"A128CBC-HS256">>,
            <<"A192CBC-HS384">>,
            <<"A256CBC-HS512">>,
            <<"A128GCM">>,
            <<"A192GCM">>,
            <<"A256GCM">>
        ]
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    application:set_env(oidcc, max_clock_skew, 10),
    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),
    application:unset_env(oidcc, max_clock_skew),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    {SignedToken, _} = jose_jwe:block_decrypt(Jwks, maps:get(<<"request">>, QueryParams)),

    {true, Jwt, _} = jose_jwt:verify(jose_jwk:from_oct(ClientSecret), SignedToken),

    #jose_jwt{
        fields = #{
            <<"nbf">> := ClientNbf
        }
    } = Jwt,

    ?assert(ClientNbf < os:system_time(seconds) - 5),
    ok.

create_redirect_url_with_request_object_no_hmac_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{} = Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"RS256">>
        ],
        request_object_encryption_alg_values_supported = [
            <<"RSA1_5">>,
            <<"RSA-OAEP">>,
            <<"RSA-OAEP-256">>,
            <<"RSA-OAEP-384">>,
            <<"RSA-OAEP-512">>,
            <<"ECDH-ES">>,
            <<"ECDH-ES+A128KW">>,
            <<"ECDH-ES+A192KW">>,
            <<"ECDH-ES+A256KW">>,
            <<"A128KW">>,
            <<"A192KW">>,
            <<"A256KW">>,
            <<"A128GCMKW">>,
            <<"A192GCMKW">>,
            <<"A256GCMKW">>,
            <<"dir">>
        ],
        request_object_encryption_enc_values_supported = [
            <<"A128CBC-HS256">>,
            <<"A192CBC-HS384">>,
            <<"A256CBC-HS512">>,
            <<"A128GCM">>,
            <<"A192GCM">>,
            <<"A256GCM">>
        ]
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"">>,

    Jwks0 = jose_jwk:to_public(jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem")),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"sig">>}},

    ClientJwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    ClientJwks = ClientJwks0#jose_jwk{fields = #{<<"use">> => <<"sig">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret, #{
            client_jwks => ClientJwks
        }),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    SignedToken = maps:get(<<"request">>, QueryParams),

    {true, _, _} = jose_jwt:verify(ClientJwks, SignedToken),

    ok.

create_redirect_url_with_invalid_request_object_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"unknown">>
        ]
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"sig">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),

    ?assertMatch(<<"https://my.provider/auth?scope=", _/binary>>, iolist_to_binary(Url)),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    ?assertEqual(
        #{
            <<"client_id">> => <<"client_id">>,
            <<"redirect_uri">> => <<"https://my.server/return">>,
            <<"response_type">> => <<"code">>,
            <<"scope">> => <<"openid">>
        },
        QueryParams
    ),

    ok.

create_redirect_url_with_missing_config_request_object_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"sig">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),

    ?assertMatch(<<"https://my.provider/auth?scope=", _/binary>>, iolist_to_binary(Url)),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    ?assertEqual(
        #{
            <<"client_id">> => <<"client_id">>,
            <<"redirect_uri">> => <<"https://my.server/return">>,
            <<"response_type">> => <<"code">>,
            <<"scope">> => <<"openid">>
        },
        QueryParams
    ),

    ok.

create_redirect_url_with_missing_config_request_object_required_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        require_signed_request_object = true
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"sig">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ?assertEqual(
        {error, request_object_required},
        oidcc_authorization:create_redirect_url(ClientContext, #{
            redirect_uri => RedirectUri
        })
    ),

    ok.

create_redirect_url_with_request_object_only_none_alg_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"none">>
        ],
        request_object_encryption_alg_values_supported = [],
        request_object_encryption_enc_values_supported = []
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),

    ?assertMatch(<<"https://my.provider/auth?scope=", _/binary>>, iolist_to_binary(Url)),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    ?assertEqual(
        #{
            <<"client_id">> => <<"client_id">>,
            <<"redirect_uri">> => <<"https://my.server/return">>,
            <<"response_type">> => <<"code">>,
            <<"scope">> => <<"openid">>
        },
        QueryParams
    ),

    ok.

create_redirect_url_with_request_object_only_none_alg_unsecured_test() ->
    PrivDir = code:priv_dir(oidcc),

    %% Enable none algorithm for test
    jose:unsecured_signing(true),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"none">>
        ],
        request_object_encryption_alg_values_supported = [
            <<"RSA1_5">>,
            <<"RSA-OAEP">>,
            <<"RSA-OAEP-256">>,
            <<"RSA-OAEP-384">>,
            <<"RSA-OAEP-512">>,
            <<"ECDH-ES">>,
            <<"ECDH-ES+A128KW">>,
            <<"ECDH-ES+A192KW">>,
            <<"ECDH-ES+A256KW">>,
            <<"A128KW">>,
            <<"A192KW">>,
            <<"A256KW">>,
            <<"A128GCMKW">>,
            <<"A192GCMKW">>,
            <<"A256GCMKW">>,
            <<"dir">>
        ],
        request_object_encryption_enc_values_supported = [
            <<"A128CBC-HS256">>,
            <<"A192CBC-HS384">>,
            <<"A256CBC-HS512">>,
            <<"A128GCM">>,
            <<"A192GCM">>,
            <<"A256GCM">>
        ]
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    {SignedToken, _} = jose_jwe:block_decrypt(Jwks, maps:get(<<"request">>, QueryParams)),

    {true, Jwt, _} = jose_jwt:verify(jose_jwk:from_oct(ClientSecret), SignedToken),

    ?assertMatch(
        #jose_jwt{
            fields = #{
                <<"aud">> := _,
                <<"client_id">> := ClientId,
                <<"exp">> := _,
                <<"iat">> := _,
                <<"iss">> := ClientId,
                <<"jti">> := _,
                <<"nbf">> := _,
                <<"redirect_uri">> := RedirectUri,
                <<"response_type">> := <<"code">>,
                <<"scope">> := <<"openid">>
            }
        },
        Jwt
    ),

    jose:unsecured_signing(false),

    ok.

create_redirect_url_with_par_required_no_url_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        require_pushed_authorization_requests = true
    },

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ?assertMatch(
        {error, par_required},
        oidcc_authorization:create_redirect_url(ClientContext, #{
            redirect_uri => RedirectUri
        })
    ),

    ok.

create_redirect_url_with_par_url_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        pushed_authorization_request_endpoint = <<"https://my.server/par">>
    },

    ParResponseData =
        jsx:encode(#{
            <<"request_uri">> => <<"urn:ietf:params:oauth:request_uri:par_response">>,
            <<"expires_in">> => 60
        }),

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,
    PkceVerifier = <<"pkce_verifier">>,
    State = <<"state">>,
    Nonce = <<"nonce">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqParEndpoint, Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            ?assertMatch(<<"https://my.server/par">>, ReqParEndpoint),
            ?assertMatch(none, proplists:lookup("authorization", Header)),
            ?assertMatch({"accept", "application/json"}, proplists:lookup("accept", Header)),
            BodyMap = maps:from_list(uri_string:dissect_query(Body)),

            ?assertMatch(
                #{
                    <<"response_type">> := <<"code">>,
                    <<"client_id">> := ClientId,
                    <<"client_secret">> := ClientSecret,
                    <<"scope">> := <<"openid">>,
                    <<"redirect_uri">> := RedirectUri,
                    <<"code_challenge">> := _,
                    <<"code_challenge_method">> := <<"S256">>,
                    <<"state">> := State,
                    <<"nonce">> := Nonce
                },
                BodyMap
            ),

            {ok, {{"HTTP/1.1", 201, "OK"}, [{"content-type", "application/json"}], ParResponseData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    RedirectUrlResponse = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri,
        pkce_verifier => PkceVerifier,
        state => State,
        nonce => Nonce
    }),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ?assertMatch(
        {ok, _},
        RedirectUrlResponse
    ),

    {ok, Url} =
        RedirectUrlResponse,
    #{
        query := QueryString
    } = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),
    ?assertEqual(
        #{
            <<"request_uri">> => <<"urn:ietf:params:oauth:request_uri:par_response">>,
            <<"client_id">> => ClientId
        },
        QueryParams
    ),

    ok.

create_redirect_url_with_par_error_when_required_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        require_pushed_authorization_requests = true,
        pushed_authorization_request_endpoint = <<"https://my.server/par">>
    },

    ParResponseData =
        jsx:encode(#{
            <<"error">> => <<"invalid_request">>
        }),

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {_Endpoint, _Header, _ContentType, _Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            {ok, {{"HTTP/1.1", 400, "OK"}, [{"content-type", "application/json"}], ParResponseData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {error, {http_error, 400, _}},
        oidcc_authorization:create_redirect_url(ClientContext, #{
            redirect_uri => RedirectUri
        })
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

create_redirect_url_with_par_invalid_response_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, _} = application:ensure_all_started(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        require_pushed_authorization_requests = false,
        pushed_authorization_request_endpoint = <<"https://my.server/par">>
    },

    %% no request_uri
    ParResponseData = jsx:encode(#{}),

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {_Endpoint, _Header, _ContentType, _Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            {ok, {{"HTTP/1.1", 201, "OK"}, [{"content-type", "application/json"}], ParResponseData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {error, {http_error, 201, _}},
        oidcc_authorization:create_redirect_url(ClientContext, #{
            redirect_uri => RedirectUri
        })
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

create_redirect_url_with_par_client_secret_jwt_request_object_test() ->
    %% https://datatracker.ietf.org/doc/html/rfc9126#section-2
    %% > To address that ambiguity, the issuer identifier URL of the authorization
    %% > server according to [RFC8414] SHOULD be used as the value of the audience.
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{issuer = Issuer} = Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),

    Configuration = Configuration0#oidcc_provider_configuration{
        pushed_authorization_request_endpoint = <<"https://my.server/par">>,
        token_endpoint_auth_methods_supported = [<<"client_secret_jwt">>],
        token_endpoint_auth_signing_alg_values_supported = [<<"HS256">>],
        request_parameter_supported = true,
        request_object_signing_alg_values_supported = [
            <<"HS256">>
        ],
        request_object_encryption_alg_values_supported = [<<"RSA-OAEP-256">>],
        request_object_encryption_enc_values_supported = [<<"A256GCM">>]
    },

    ParResponseData =
        jsx:encode(#{
            <<"request_uri">> => <<"urn:ietf:params:oauth:request_uri:par_response">>,
            <<"expires_in">> => 60
        }),

    ClientId = <<"client_id">>,
    ClientSecret = <<"at_least_32_character_client_secret">>,

    Jwks0 = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    Jwks = Jwks0#jose_jwk{fields = #{<<"use">> => <<"enc">>}},

    RedirectUri = <<"https://my.server/return">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {_Endpoint, _Header, "application/x-www-form-urlencoded", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            BodyParsed = uri_string:dissect_query(Body),
            BodyMap = maps:from_list(BodyParsed),

            %% no duplicate parameters
            ?assertEqual(length(BodyParsed), map_size(BodyMap)),

            ?assertMatch(
                #{
                    <<"client_id">> := ClientId,
                    <<"client_assertion_type">> :=
                        <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>,
                    <<"client_assertion">> := _,
                    <<"request">> := _
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

            {SignedToken, Jwe} = jose_jwe:block_decrypt(Jwks, maps:get(<<"request">>, BodyMap)),

            ?assertMatch(#jose_jwe{alg = {jose_jwe_alg_rsa, _}}, Jwe),

            {true, Jwt, Jws} = jose_jwt:verify(jose_jwk:from_oct(ClientSecret), SignedToken),

            ?assertMatch(#jose_jws{alg = {jose_jws_alg_hmac, 'HS256'}}, Jws),

            ?assertMatch(
                #jose_jwt{
                    fields = #{
                        <<"aud">> := Issuer,
                        <<"client_id">> := ClientId,
                        <<"exp">> := _,
                        <<"iat">> := _,
                        <<"iss">> := ClientId,
                        <<"jti">> := _,
                        <<"nbf">> := _,
                        <<"redirect_uri">> := RedirectUri,
                        <<"response_type">> := <<"code">>,
                        <<"scope">> := <<"openid">>
                    }
                },
                Jwt
            ),

            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], ParResponseData}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => RedirectUri
    }),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ?assertMatch(<<"https://my.provider/auth?request_uri=", _/binary>>, iolist_to_binary(Url)),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    ?assertMatch(
        #{
            <<"client_id">> := <<"client_id">>,
            <<"request_uri">> := <<"urn:ietf:params:oauth:request_uri:par_response">>
        },
        QueryParams
    ),

    ok.

create_redirect_url_private_key_jwt_test() ->
    ClientContext = private_key_jwt_fixture(),
    RedirectUri = <<"https://my.server/return">>,

    Opts =
        #{
            redirect_uri => RedirectUri
        },

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, Opts),

    ExpUrl =
        <<"https://my.provider/auth?dpop_jkt=7jnO2y748F6HEP7WtfubjBQWOgKUuMBQoYLyyc1fe-Q&scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn">>,
    ?assertEqual(ExpUrl, iolist_to_binary(Url)),

    ok.

create_redirect_url_response_mode_jwt_test() ->
    ClientContext = private_key_jwt_fixture(),
    RedirectUri = <<"https://my.server/return">>,

    Opts =
        #{
            redirect_uri => RedirectUri
        },

    {ok, Url1} = oidcc_authorization:create_redirect_url(ClientContext, Opts#{
        response_mode => <<"jwt">>
    }),
    {ok, Url2} = oidcc_authorization:create_redirect_url(ClientContext, Opts#{
        response_mode => <<"query.jwt">>
    }),

    ?assertMatch(
        #{
            "response_mode" := "jwt"
        },
        parse_query_string(Url1)
    ),

    ?assertMatch(
        #{
            "response_mode" := "query.jwt"
        },
        parse_query_string(Url2)
    ),

    ok.

private_key_jwt_fixture() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} = oidcc_provider_configuration:decode_configuration(
        jose:decode(ValidConfigString)
    ),
    Configuration = Configuration0#oidcc_provider_configuration{
        token_endpoint_auth_methods_supported = [<<"private_key_jwt">>],
        dpop_signing_alg_values_supported = [<<"RS256">>]
    },

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    ClientId = <<"client_id">>,

    ClientContext =
        oidcc_client_context:from_manual(Configuration, Jwks, ClientId, <<"client_secret">>, #{
            client_jwks => Jwks
        }),

    ClientContext.

parse_query_string(UriString) ->
    #{query := QueryStringBinary} = uri_string:parse(UriString),
    QueryList = uri_string:dissect_query(QueryStringBinary),
    maps:from_list(QueryList).
