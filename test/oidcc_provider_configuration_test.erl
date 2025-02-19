%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_provider_configuration_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

decode_google_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/google-metadata.json"),
    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://accounts.google.com">>,
            token_endpoint =
                <<"https://oauth2.googleapis.com/token">>,
            userinfo_endpoint =
                <<"https://openidconnect.googleapis.com/v1/userinfo">>,
            jwks_uri =
                <<"https://www.googleapis.com/oauth2/v3/certs">>,
            registration_endpoint = undefined,
            scopes_supported =
                [<<"openid">>, <<"email">>, <<"profile">>],
            response_types_supported =
                [
                    <<"code">>,
                    <<"token">>,
                    <<"id_token">>,
                    <<"code token">>,
                    <<"code id_token">>,
                    <<"token id_token">>,
                    <<"code token id_token">>,
                    <<"none">>
                ],
            response_modes_supported =
                [<<"query">>, <<"fragment">>],
            grant_types_supported =
                [
                    <<"authorization_code">>,
                    <<"refresh_token">>,
                    <<"urn:ietf:params:oauth:grant-type:device_code">>,
                    <<"urn:ietf:params:oauth:grant-type:jwt-bearer">>
                ],
            acr_values_supported = undefined,
            subject_types_supported = [public],
            id_token_signing_alg_values_supported =
                [<<"RS256">>],
            id_token_encryption_alg_values_supported =
                undefined,
            id_token_encryption_enc_values_supported =
                undefined,
            userinfo_signing_alg_values_supported = undefined,
            userinfo_encryption_alg_values_supported =
                undefined,
            userinfo_encryption_enc_values_supported =
                undefined,
            request_object_signing_alg_values_supported =
                undefined,
            request_object_encryption_alg_values_supported =
                undefined,
            request_object_encryption_enc_values_supported =
                undefined,
            token_endpoint_auth_methods_supported =
                [
                    <<"client_secret_post">>,
                    <<"client_secret_basic">>
                ],
            token_endpoint_auth_signing_alg_values_supported =
                undefined,
            display_values_supported = undefined,
            claim_types_supported = [normal],
            claims_supported =
                [
                    <<"aud">>,
                    <<"email">>,
                    <<"email_verified">>,
                    <<"exp">>,
                    <<"family_name">>,
                    <<"given_name">>,
                    <<"iat">>,
                    <<"iss">>,
                    <<"locale">>,
                    <<"name">>,
                    <<"picture">>,
                    <<"sub">>
                ],
            service_documentation = undefined,
            claims_locales_supported = undefined,
            ui_locales_supported = undefined,
            claims_parameter_supported = false,
            request_parameter_supported = false,
            request_uri_parameter_supported = true,
            require_request_uri_registration = false,
            op_policy_uri = undefined,
            op_tos_uri = undefined,
            revocation_endpoint =
                <<"https://oauth2.googleapis.com/revoke">>,
            revocation_endpoint_auth_methods_supported =
                [<<"client_secret_basic">>],
            revocation_endpoint_auth_signing_alg_values_supported =
                undefined,
            introspection_endpoint = undefined,
            introspection_endpoint_auth_methods_supported =
                [<<"client_secret_basic">>],
            introspection_endpoint_auth_signing_alg_values_supported =
                undefined,
            code_challenge_methods_supported =
                [<<"plain">>, <<"S256">>],
            extra_fields =
                #{
                    <<"device_authorization_endpoint">> :=
                        <<"https://oauth2.googleapis.com/device/code">>
                }
        }},
        oidcc_provider_configuration:decode_configuration(jose:decode(Configuration))
    ).

check_validations_test() ->
    ?assertMatch(
        {error, {invalid_config_property, {uri, issuer}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"issuer">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, authorization_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"authorization_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, token_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri_https, userinfo_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri_https, userinfo_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    <<"file:///foo">>
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, jwks_uri}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"jwks_uri">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, registration_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"registration_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, scopes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"scopes_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, scopes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"scopes_supported">> =>
                    [
                        <<"test">>,
                        7
                    ]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {scopes_including_openid, scopes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"scopes_supported">> =>
                    [<<"without openid">>]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, response_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"response_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, response_modes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"response_modes_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, grant_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"grant_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, acr_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"acr_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, subject_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"subject_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {enum, subject_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"subject_types_supported">> =>
                    [
                        <<"pairwise">>,
                        <<"public">>,
                        <<"invalid">>
                    ]
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, id_token_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"id_token_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, id_token_encryption_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"id_token_encryption_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, id_token_encryption_enc_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"id_token_encryption_enc_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, userinfo_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, userinfo_encryption_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_encryption_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, userinfo_encryption_enc_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_encryption_enc_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, request_object_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_object_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, request_object_encryption_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_object_encryption_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, request_object_encryption_enc_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_object_encryption_enc_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, token_endpoint_auth_methods_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint_auth_methods_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, token_endpoint_auth_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint_auth_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {alg_no_none, token_endpoint_auth_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint_auth_signing_alg_values_supported">> =>
                    [
                        <<"something">>,
                        <<"none">>
                    ]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, display_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"display_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, claim_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claim_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {enum, claim_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claim_types_supported">> =>
                    [
                        <<"normal">>,
                        <<"aggregated">>,
                        <<"distributed">>,
                        <<"invalid">>
                    ]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, claims_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claims_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, service_documentation}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"service_documentation">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, claims_locales_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claims_locales_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, ui_locales_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"ui_locales_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {boolean, claims_parameter_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claims_parameter_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {boolean, request_parameter_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_parameter_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {boolean, request_uri_parameter_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_uri_parameter_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, op_policy_uri}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"op_policy_uri">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, op_tos_uri}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"op_tos_uri">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {missing_config_property, issuer}},
        oidcc_provider_configuration:decode_configuration(#{})
    ),

    ok.

allow_unsafe_http_quirk_test() ->
    ?assertMatch(
        {error, {invalid_config_property, {uri_https, userinfo_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    <<"http://example.com">>
            })
        )
    ),
    ?assertMatch(
        {ok, _},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    <<"http://example.com">>
            }),
            #{quirks => #{allow_unsafe_http => true}}
        )
    ),

    ok.

document_overrides_quirk_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/google-metadata.json"),

    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://example.com">>
        }},
        oidcc_provider_configuration:decode_configuration(jose:decode(Configuration), #{
            quirks => #{document_overrides => #{<<"issuer">> => <<"https://example.com">>}}
        })
    ),
    ok.

uri_concatenation_test() ->
    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(get, {ReqEndpoint, _Header}, _HttpOpts, _Opts, _Profile) ->
            self() ! {req, ReqEndpoint},

            {ok, {{"HTTP/1.1", 501, "Not Implemented"}, [], ""}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    oidcc_provider_configuration:load_configuration("https://example.com"),

    receive
        {req, "https://example.com/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    oidcc_provider_configuration:load_configuration("https://example.com/"),

    receive
        {req, "https://example.com/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    oidcc_provider_configuration:load_configuration("https://example.com/realm"),

    receive
        {req, "https://example.com/realm/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    oidcc_provider_configuration:load_configuration("https://example.com/realm/"),

    receive
        {req, "https://example.com/realm/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    meck:unload(httpc),

    ok.

decode_fapi2_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/fapi2-metadata.json"),
    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://my.provider">>,
            tls_client_certificate_bound_access_tokens = true,
            mtls_endpoint_aliases = #{
                <<"authorization_endpoint">> := <<"https://my.provider/tls/auth">>,
                <<"registration_endpoint">> := <<"https://my.provider/tls/register">>,
                <<"device_authorization_endpoint">> := <<"https://my.provider/tls/device/code">>,
                <<"token_endpoint">> := <<"https://my.provider/tls/token">>,
                <<"introspection_endpoint">> := <<"https://my.provider/tls/introspection">>,
                <<"userinfo_endpoint">> := <<"https://my.provider/tls/userinfo">>
            }
        }},
        oidcc_provider_configuration:decode_configuration(jose:decode(Configuration))
    ),

    ok.

google_merge_json(Merge) ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/google-metadata.json"),
    Decoded = jose:decode(ValidConfigString),
    maps:merge(Decoded, Merge).
