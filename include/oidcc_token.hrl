%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-ifndef(OIDCC_TOKEN_HRL).

-record(oidcc_token_id, {token :: binary(), claims :: oidcc_jwt_util:claims()}).
-record(oidcc_token_access, {
    token :: binary(),
    expires = undefined :: pos_integer() | undefined,
    type = <<"Bearer">> :: binary()
}).
-record(oidcc_token_refresh, {token :: binary()}).
-record(oidcc_token, {
    id :: oidcc_token:id() | none,
    access :: oidcc_token:access() | none,
    refresh :: oidcc_token:refresh() | none,
    scope :: oidcc_scope:scopes()
}).

-define(OIDCC_TOKEN_HRL, 1).

-endif.
