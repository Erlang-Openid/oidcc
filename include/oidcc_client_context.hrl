%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-ifndef(OIDCC_CLIENT_CONTEXT_HRL).

-record(oidcc_client_context, {
    provider_configuration :: oidcc_provider_configuration:t(),
    jwks :: jose_jwk:key(),
    client_id :: binary(),
    client_secret :: binary() | unauthenticated,
    client_jwks = none :: jose_jwk:key() | none
}).

-define(OIDCC_CLIENT_CONTEXT_HRL, 1).

-endif.
