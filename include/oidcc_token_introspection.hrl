%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-ifndef(OIDCC_TOKEN_INTROSPECTION_HRL).

%% @see https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
-record(oidcc_token_introspection, {
    active :: boolean(),
    client_id :: binary(),
    exp :: pos_integer() | undefined,
    scope :: oidcc_scope:scopes(),
    username :: binary() | undefined,
    token_type :: binary() | undefined,
    iat :: pos_integer() | undefined,
    nbf :: pos_integer() | undefined,
    sub :: binary() | undefined,
    aud :: binary() | undefined,
    iss :: binary() | undefined,
    jti :: binary() | undefined,
    extra :: #{binary() := term()}
}).

-define(OIDCC_TOKEN_INTROSPECTION_HRL, 1).

-endif.
