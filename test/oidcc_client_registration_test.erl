%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_client_registration_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_client_registration.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

register_test() ->
    {ok, _} = application:ensure_all_started(oidcc),

    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{registration_endpoint = RegistrationEndpoint} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),

    RedirectUri = <<"https://example.com/oidcc/callback">>,

    Registration = #oidcc_client_registration{
        redirect_uris = [RedirectUri],
        jwks = Jwks
    },

    ClientId = <<"client_id">>,

    ResponseJson = jose:encode(#{
        client_id => ClientId,
        client_id_issued_at => erlang:system_time(second)
    }),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [
                [oidcc, register_client, start],
                [oidcc, register_client, stop]
            ]
        ),

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/json", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            RegistrationEndpoint = ReqEndpoint,

            ?assertMatch(
                #{
                    <<"application_type">> := <<"web">>,
                    <<"redirect_uris">> := [RedirectUri],
                    <<"require_auth_time">> := false,
                    <<"token_endpoint_auth_method">> := <<"client_secret_basic">>
                },
                jose:decode(Body)
            ),
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], ResponseJson}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    {ok, Response} = oidcc_client_registration:register(Configuration, Registration, #{
        initial_access_token => <<"token">>
    }),
    {ok, Response} = oidcc_client_registration:register(Configuration, Registration, #{}),

    ?assertMatch(#oidcc_client_registration_response{client_id = ClientId}, Response),

    receive
        {[oidcc, register_client, start], TelemetryRef, #{}, #{
            issuer := <<"https://my.provider">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    receive
        {[oidcc, register_client, stop], TelemetryRef, #{duration := _Duration}, #{
            issuer := <<"https://my.provider">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.

registration_not_supported_test() ->
    {ok, _} = application:ensure_all_started(oidcc),

    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration0} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Configuration = Configuration0#oidcc_provider_configuration{registration_endpoint = undefined},

    RedirectUri = <<"https://example.com/oidcc/callback">>,

    Registration = #oidcc_client_registration{
        redirect_uris = [RedirectUri]
    },

    ?assertMatch(
        {error, registration_not_supported},
        oidcc_client_registration:register(Configuration, Registration, #{})
    ),

    ok.

registration_invalid_response_test() ->
    {ok, _} = application:ensure_all_started(oidcc),

    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok,
        #oidcc_provider_configuration{registration_endpoint = RegistrationEndpoint} =
            Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    RedirectUri = <<"https://example.com/oidcc/callback">>,

    ClientId = <<"client_id">>,

    JwtRegistration = #oidcc_client_registration{
        redirect_uris = [RedirectUri],
        client_name = <<"jwt">>
    },

    ErrorRegistration = #oidcc_client_registration{
        redirect_uris = [RedirectUri],
        client_name = <<"error">>
    },

    InvalidFieldsRegistration = #oidcc_client_registration{
        redirect_uris = [RedirectUri],
        client_name = <<"invalid_fields">>
    },

    InvalidIssuedAtRegistration = #oidcc_client_registration{
        redirect_uris = [RedirectUri],
        client_name = <<"invalid_client_id_issued_at">>
    },

    InvalidClientIdRegistration = #oidcc_client_registration{
        redirect_uris = [RedirectUri],
        client_name = <<"invalid_client_id">>
    },

    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(
            post,
            {ReqEndpoint, _Header, "application/json", Body},
            _HttpOpts,
            _Opts,
            _Profile
        ) ->
            RegistrationEndpoint = ReqEndpoint,

            case jose:decode(Body) of
                #{<<"client_name">> := <<"jwt">>} ->
                    {ok, {
                        {"HTTP/1.1", 200, "OK"},
                        [{"content-type", "application/jwt"}],
                        <<"irrelevant">>
                    }};
                #{<<"client_name">> := <<"error">>} ->
                    {error, reason};
                #{<<"client_name">> := <<"invalid_fields">>} ->
                    {ok, {
                        {"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], <<"{}">>
                    }};
                #{<<"client_name">> := <<"invalid_client_id_issued_at">>} ->
                    {ok, {
                        {"HTTP/1.1", 200, "OK"},
                        [{"content-type", "application/json"}],
                        jose:encode(#{client_id => ClientId, client_id_issued_at => <<"invalid">>})
                    }};
                #{<<"client_name">> := <<"invalid_client_id">>} ->
                    {ok, {
                        {"HTTP/1.1", 200, "OK"},
                        [{"content-type", "application/json"}],
                        jose:encode(#{client_id => 7})
                    }}
            end
        end,
    ok = meck:expect(httpc, request, HttpFun),

    ?assertMatch(
        {error, invalid_content_type},
        oidcc_client_registration:register(Configuration, JwtRegistration, #{})
    ),
    ?assertMatch(
        {error, reason}, oidcc_client_registration:register(Configuration, ErrorRegistration, #{})
    ),
    ?assertMatch(
        {error, {missing_config_property, client_id}},
        oidcc_client_registration:register(Configuration, InvalidFieldsRegistration, #{})
    ),
    ?assertMatch(
        {error, {invalid_config_property, {number, client_id_issued_at}}},
        oidcc_client_registration:register(Configuration, InvalidIssuedAtRegistration, #{})
    ),
    ?assertMatch(
        {error, {invalid_config_property, {binary, client_id}}},
        oidcc_client_registration:register(Configuration, InvalidClientIdRegistration, #{})
    ),

    true = meck:validate(httpc),

    meck:unload(httpc),

    ok.
