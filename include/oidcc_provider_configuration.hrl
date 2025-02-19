%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-ifndef(oidcc_provider_configuration_HRL).

%% @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
%% @see https://datatracker.ietf.org/doc/html/draft-jones-oauth-discovery-01#section-4.1
%% @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
-record(oidcc_provider_configuration,
    %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
    {
        issuer :: uri_string:uri_string(),
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        authorization_endpoint :: uri_string:uri_string(),
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        token_endpoint = undefined :: uri_string:uri_string() | undefined,
        %% OpenID Connect Discovery 1.0
        userinfo_endpoint = undefined :: uri_string:uri_string() | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        jwks_uri = undefined :: uri_string:uri_string() | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        registration_endpoint = undefined :: uri_string:uri_string() | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        scopes_supported :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        response_types_supported :: [binary()],
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        response_modes_supported = [<<"query">>, <<"fragment">>] :: [binary()],
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        grant_types_supported = [<<"authorization_code">>, <<"implicit">>] :: [binary()],
        %% OpenID Connect Discovery 1.0
        acr_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        subject_types_supported :: [pairwise | public],
        %% OpenID Connect Discovery 1.0
        id_token_signing_alg_values_supported :: [binary()],
        %% OpenID Connect Discovery 1.0
        id_token_encryption_alg_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        id_token_encryption_enc_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        userinfo_signing_alg_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        userinfo_encryption_alg_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        userinfo_encryption_enc_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        request_object_signing_alg_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        request_object_encryption_alg_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        request_object_encryption_enc_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        token_endpoint_auth_methods_supported = [<<"client_secret_basic">>] :: [binary()],
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        token_endpoint_auth_signing_alg_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        display_values_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        claim_types_supported = [normal] :: [normal | aggregated | distributed],
        %% OpenID Connect Discovery 1.0
        claims_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        service_documentation = undefined :: uri_string:uri_string() | undefined,
        %% OpenID Connect Discovery 1.0
        claims_locales_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        ui_locales_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect Discovery 1.0
        claims_parameter_supported = false :: boolean(),
        %% OpenID Connect Discovery 1.0
        request_parameter_supported = false :: boolean(),
        %% OpenID Connect Discovery 1.0
        request_uri_parameter_supported = true :: boolean(),
        %% OpenID Connect Discovery 1.0
        require_request_uri_registration = false :: boolean(),
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        op_policy_uri = undefined :: uri_string:uri_string() | undefined,
        %% OpenID Connect Discovery 1.0 / OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        op_tos_uri = undefined :: uri_string:uri_string() | undefined,
        %% OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        revocation_endpoint = undefined :: uri_string:uri_string() | undefined,
        %% OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        revocation_endpoint_auth_methods_supported = [<<"client_secret_basic">>] :: [binary()],
        %% OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        revocation_endpoint_auth_signing_alg_values_supported = undefined ::
            [binary()] | undefined,
        %% OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        introspection_endpoint = undefined :: uri_string:uri_string() | undefined,
        %% OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        introspection_endpoint_auth_methods_supported = [<<"client_secret_basic">>] :: [binary()],
        %% OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        introspection_endpoint_auth_signing_alg_values_supported = undefined ::
            [binary()] | undefined,
        %% OAuth 2.0 Discovery (draft-jones-oauth-discovery-01)
        code_challenge_methods_supported = undefined :: [binary()] | undefined,
        %% OpenID Connect RP-Initiated Logout 1.0
        end_session_endpoint = undefined :: uri_string:uri_string() | undefined,
        %% OAuth 2.0 Pushed Authorization Requests
        require_pushed_authorization_requests = false :: boolean(),
        %% OAuth 2.0 Pushed Authorization Requests
        pushed_authorization_request_endpoint = undefined :: uri_string:uri_string() | undefined,
        %% JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)
        authorization_signing_alg_values_supported = undefined :: [binary()] | undefined,
        %% JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)
        authorization_encryption_alg_values_supported = undefined :: [binary()] | undefined,
        %% JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)
        authorization_encryption_enc_values_supported = undefined :: [binary()] | undefined,
        %% OAuth 2.0 Authorization Server Issuer Identification (RFC9207)
        authorization_response_iss_parameter_supported = false :: boolean(),
        %% OAuth 2.0 Demonstrating Proof of Possession (DPoP)
        dpop_signing_alg_values_supported = undefined :: [binary()] | undefined,
        %% RFC 9101 The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)
        require_signed_request_object = false :: boolean(),
        %% RFC 8705 OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
        mtls_endpoint_aliases = #{} :: #{binary() => uri_string:uri_string()},
        %% RFC 8705 OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
        tls_client_certificate_bound_access_tokens = false :: boolean(),
        %% Unknown Fields
        extra_fields = #{} :: #{binary() => term()}
    }
).

-define(oidcc_provider_configuration_HRL, 1).

-endif.
