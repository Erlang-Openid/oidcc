%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_provider_configuration_worker_SUITE).

-export([all/0]).
-export([end_per_suite/1]).
-export([errors_on_invalid_issuer/1]).
-export([init_per_suite/1]).
-export([refreshes_after_timeout/1]).
-export([refreshes_jwks_on_missing_kid/1]).
-export([retrieves_configuration/1]).
-export([retrieves_jwks/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [
        retrieves_configuration,
        retrieves_jwks,
        errors_on_invalid_issuer,
        refreshes_jwks_on_missing_kid,
        refreshes_after_timeout
    ].

init_per_suite(_Config) ->
    {ok, _} = application:ensure_all_started(oidcc),
    [].

end_per_suite(_Config) ->
    ok.

retrieves_configuration(_Config) ->
    WorkerName = retrieves_configuration_oidcc_provider_configuration_worker_SUITE,

    {ok, GoogleConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://accounts.google.com">>,
            name => {local, WorkerName}
        }),

    ?assertMatch(
        #oidcc_provider_configuration{
            token_endpoint =
                <<"https://oauth2.googleapis.com/token">>
        },
        oidcc_provider_configuration_worker:get_provider_configuration(
            WorkerName
        )
    ),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [
                [oidcc, load_configuration, start],
                [oidcc, load_configuration, stop]
            ]
        ),

    oidcc_provider_configuration_worker:refresh_configuration(GoogleConfigurationPid),

    receive
        {[oidcc, load_configuration, start], TelemetryRef, #{}, #{
            issuer := <<"https://accounts.google.com">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    receive
        {[oidcc, load_configuration, stop], TelemetryRef, #{duration := _Duration}, #{
            issuer := <<"https://accounts.google.com">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    ?assertMatch(
        #oidcc_provider_configuration{},
        oidcc_provider_configuration_worker:get_provider_configuration(WorkerName)
    ),

    ok.

retrieves_jwks(_Config) ->
    {ok, GoogleConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://accounts.google.com">>
        }),

    ?assertMatch(
        #jose_jwk{keys = _Keys},
        oidcc_provider_configuration_worker:get_jwks(GoogleConfigurationPid)
    ),

    TelemetryRef =
        telemetry_test:attach_event_handlers(
            self(),
            [[oidcc, load_jwks, start], [oidcc, load_jwks, stop]]
        ),

    oidcc_provider_configuration_worker:refresh_jwks(GoogleConfigurationPid),

    receive
        {[oidcc, load_jwks, start], TelemetryRef, #{}, #{
            jwks_uri := <<"https://www.googleapis.com/oauth2/v3/certs">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    receive
        {[oidcc, load_jwks, stop], TelemetryRef, #{duration := _Duration}, #{
            jwks_uri := <<"https://www.googleapis.com/oauth2/v3/certs">>
        }} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    ?assertMatch(
        #jose_jwk{keys = _Keys},
        oidcc_provider_configuration_worker:get_jwks(GoogleConfigurationPid)
    ).

refreshes_jwks_on_missing_kid(_Config) ->
    {ok, GoogleConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://accounts.google.com">>
        }),

    #jose_jwk{
        keys =
            {jose_jwk_set, [#jose_jwk{fields = #{<<"kid">> := ExistingKid}} | _Rest]}
    } = oidcc_provider_configuration_worker:get_jwks(GoogleConfigurationPid),

    TelemetryRef = telemetry_test:attach_event_handlers(self(), [[oidcc, load_jwks, start]]),

    oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(
        GoogleConfigurationPid,
        "kid"
    ),

    ?assertMatch(
        #jose_jwk{keys = _Keys},
        oidcc_provider_configuration_worker:get_jwks(GoogleConfigurationPid)
    ),

    receive
        {[oidcc, load_jwks, start], TelemetryRef, #{}, #{}} ->
            ok
    after 10_000 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(
        GoogleConfigurationPid,
        ExistingKid
    ),

    receive
        {[oidcc, load_jwks, start], TelemetryRef, #{}, #{}} ->
            ct:fail(should_not_trigger_refresh)
    after 1_000 ->
        ok
    end.

refreshes_after_timeout(_Config) ->
    {ok, YahooConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://api.login.yahoo.com">>,
            provider_configuration_opts => #{fallback_expiry => 100}
        }),

    ?assertMatch(
        #oidcc_provider_configuration{},
        oidcc_provider_configuration_worker:get_provider_configuration(YahooConfigurationPid)
    ),

    TelemetryRef =
        telemetry_test:attach_event_handlers(self(), [[oidcc, load_configuration, start]]),

    receive
        {[oidcc, load_configuration, start], TelemetryRef, #{}, #{}} ->
            ok
    after 1_000 ->
        ct:fail(should_refresh_automatically)
    end.

errors_on_invalid_issuer(_Config) ->
    process_flag(trap_exit, true),

    ?assertExit(
        {{configuration_load_failed, {http_error, 404, _}}, _},
        initialize_invalid_issuer()
    ).

initialize_invalid_issuer() ->
    {ok, Pid} =
        oidcc_provider_configuration_worker:start_link(#{issuer => <<"https://example.com/">>}),

    oidcc_provider_configuration_worker:get_provider_configuration(Pid).
