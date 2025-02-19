%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_auth_util_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").

add_client_authentication_no_supported_auth_method_test() ->
    ?assertMatch(
        {error, no_supported_auth_method},
        oidcc_auth_util:add_client_authentication(
            [], [], undefined, [], #{}, #oidcc_client_context{}
        )
    ),

    ?assertMatch(
        {error, no_supported_auth_method},
        oidcc_auth_util:add_client_authentication([], [], [], [], #{}, #oidcc_client_context{})
    ),

    ?assertMatch(
        {error, no_supported_auth_method},
        oidcc_auth_util:add_client_authentication(
            [], [], [<<"client_secret_basic">>], ["HS256"], #{}, #oidcc_client_context{
                client_secret = unauthenticated
            }
        )
    ).
