%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-ifndef(OIDCC_CLIENT_REGISTRATION_HRL).

%% @see https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
%% @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata
-record(oidcc_client_registration, {
    %% OpenID Connect Dynamic Client Registration 1.0
    redirect_uris :: [uri_string:uri_string()],
    %% OpenID Connect Dynamic Client Registration 1.0
    response_types = undefined :: [binary()] | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    grant_types = undefined :: [binary()] | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    application_type = web :: web | native,
    %% OpenID Connect Dynamic Client Registration 1.0
    contacts = undefined :: [binary()] | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    client_name = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    logo_uri = undefined :: uri_string:uri_string() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    client_uri = undefined :: uri_string:uri_string() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    policy_uri = undefined :: uri_string:uri_string() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    tos_uri = undefined :: uri_string:uri_string() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    jwks = undefined :: jose_jwk:key() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    jwks_uri = undefined :: uri_string:uri_string() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    sector_identifier_uri = undefined :: uri_string:uri_string() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    subject_type = undefined :: pairwise | public | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    id_token_signed_response_alg = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    id_token_encrypted_response_alg = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    id_token_encrypted_response_enc = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    userinfo_signed_response_alg = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    userinfo_encrypted_response_alg = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    userinfo_encrypted_response_enc = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    request_object_signing_alg = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    request_object_encryption_alg = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    request_object_encryption_enc = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    token_endpoint_auth_method = <<"client_secret_basic">> :: binary(),
    %% OpenID Connect Dynamic Client Registration 1.0
    token_endpoint_auth_signing_alg = undefined :: binary() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    default_max_age = undefined :: pos_integer() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    require_auth_time = false :: boolean(),
    %% OpenID Connect Dynamic Client Registration 1.0
    default_acr_values = undefined :: [binary()] | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    initiate_login_uri = undefined :: uri_string:uri_string() | undefined,
    %% OpenID Connect Dynamic Client Registration 1.0
    request_uris = undefined :: [uri_string:uri_string()] | undefined,
    %% OpenID Connect RP-Initiated Logout 1.0
    post_logout_redirect_uris = undefined :: [uri_string:uri_string()] | undefined,
    %% OAuth 2.0 Pushed Authorization Requests
    require_pushed_authorization_requests = false :: boolean(),
    %% OAuth 2.0 Demonstrating Proof of Possession (DPoP)
    dpop_bound_access_tokens = false :: boolean(),
    %% Unknown Fields
    extra_fields = #{} :: #{binary() => term()}
}).

%% @see https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
-record(oidcc_client_registration_response, {
    client_id :: binary(),
    client_secret = undefined :: binary() | undefined,
    registration_access_token = undefined :: binary() | undefined,
    registration_client_uri = undefined :: uri_string:uri_string() | undefined,
    client_id_issued_at = undefined :: pos_integer() | undefined,
    client_secret_expires_at = undefined :: pos_integer() | undefined,
    %% Unknown Fields
    extra_fields = #{} :: #{binary() => term()}
}).

-define(OIDCC_CLIENT_REGISTRATION_HRL, 1).

-endif.
