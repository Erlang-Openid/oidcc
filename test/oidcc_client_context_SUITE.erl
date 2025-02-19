%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_client_context_SUITE).

-export([all/0]).
-export([from_configuration_worker/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [from_configuration_worker].

from_configuration_worker(_Config) ->
    {ok, GoogleConfigurationPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://accounts.google.com">>,
            name => {local, from_configuration_worker_oidcc_client_context_SUITE}
        }),

    Configuration = oidcc_provider_configuration_worker:get_provider_configuration(
        GoogleConfigurationPid
    ),
    Jwks = oidcc_provider_configuration_worker:get_jwks(GoogleConfigurationPid),

    ?assertMatch(
        {ok, #oidcc_client_context{
            provider_configuration = Configuration,
            jwks = Jwks,
            client_id = <<"client_id">>,
            client_secret = <<"client_secret">>
        }},
        oidcc_client_context:from_configuration_worker(
            from_configuration_worker_oidcc_client_context_SUITE,
            <<"client_id">>,
            <<"client_secret">>
        )
    ),

    ok.
