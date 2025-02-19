%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_provider_configuration_SUITE).

-export([all/0]).
-export([load_configuration/1]).
-export([load_configuration_issuer_mismatch/1]).
-export([load_jwks/1]).
-export([load_well_known_openid_introspections/1]).
-export([reads_configuration_expiry/1]).

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [
        load_configuration,
        load_configuration_issuer_mismatch,
        load_jwks,
        reads_configuration_expiry,
        load_well_known_openid_introspections
    ].

load_configuration(_Config) ->
    ?assertMatch(
        {ok, {
            #oidcc_provider_configuration{
                token_endpoint =
                    <<"https://oauth2.googleapis.com/token">>
            },
            3_600_000
        }},
        oidcc_provider_configuration:load_configuration(
            <<"https://accounts.google.com">>,
            #{}
        )
    ).

load_configuration_issuer_mismatch(_Config) ->
    ?assertMatch(
        {error, {issuer_mismatch, <<"https://accounts.google.com">>}},
        oidcc_provider_configuration:load_configuration(
            <<"https://accounts.google.com/">>,
            #{}
        )
    ).

load_jwks(_Config) ->
    ?assertMatch(
        {ok, {#jose_jwk{keys = _Keys}, _}},
        oidcc_provider_configuration:load_jwks(
            <<"https://www.googleapis.com/oauth2/v3/certs">>,
            #{}
        )
    ).

reads_configuration_expiry(_Config) ->
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, 3_600_000}},
        oidcc_provider_configuration:load_configuration(
            <<"https://accounts.google.com">>,
            #{}
        )
    ).

load_well_known_openid_introspections(_Config) ->
    %% Google
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _}},
        oidcc_provider_configuration:load_configuration(
            <<"https://accounts.google.com">>,
            #{}
        )
    ),

    %% Yahoo
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _}},
        oidcc_provider_configuration:load_configuration(
            <<"https://api.login.yahoo.com">>,
            #{}
        )
    ),

    %% Salesforce
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _}},
        oidcc_provider_configuration:load_configuration(
            <<"https://login.salesforce.com">>,
            #{}
        )
    ),

    %% Test Instance of Zitadel
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _}},
        oidcc_provider_configuration:load_configuration(
            <<"https://erlef-test-w4a8z2.zitadel.cloud">>,
            #{}
        )
    ),

    %% Auth0
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _}},
        oidcc_provider_configuration:load_configuration(
            <<"https://dev-key.us.auth0.com/">>,
            #{}
        )
    ),

    %% Microsoft
    ?assertMatch(
        {error, {issuer_mismatch, _}},
        oidcc_provider_configuration:load_configuration(
            <<"https://login.microsoftonline.com/common/v2.0">>,
            #{}
        )
    ),
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _}},
        oidcc_provider_configuration:load_configuration(
            <<"https://login.microsoftonline.com/common/v2.0">>,
            #{quirks => #{allow_issuer_mismatch => true}}
        )
    ),

    ok.
