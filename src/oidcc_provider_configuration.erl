%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_provider_configuration).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("""
Tooling to load and parse Openid Configuration.

## Records

To use the record, import the definition:

```erlang
-include_lib(["oidcc/include/oidcc_provider_configuration.hrl"]).
```

## Telemetry

See [`Oidcc.ProviderConfiguration`](`m:'Elixir.Oidcc.ProviderConfiguration'`).
""").
?MODULEDOC(#{since => <<"3.0.0">>}).

-include("oidcc_provider_configuration.hrl").

-export([decode_configuration/1]).
-export([decode_configuration/2]).
-export([load_configuration/1]).
-export([load_configuration/2]).
-export([load_jwks/2]).

-export_type([error/0]).
-export_type([opts/0]).
-export_type([quirks/0]).
-export_type([t/0]).

?DOC("""
Allow Specification Non-compliance.

## Exceptions

* `allow_unsafe_http` - Allow unsafe HTTP. Use this for development
  providers and **never in production**.
* `document_overrides` - a map to merge with the real OIDD document,
  in case the OP left out some values.
""").
?DOC(#{since => <<"3.1.0">>}).
-type quirks() :: #{
    allow_unsafe_http => boolean(),
    document_overrides => map()
}.

?DOC("""
Configure configuration loading / parsing.

## Parameters

* `fallback_expiry` - How long to keep configuration cached if the server doesn't specify expiry.
* `request_opts` - config for HTTP request.
""").
?DOC(#{since => <<"3.0.0">>}).
-type opts() :: #{
    fallback_expiry => timeout(),
    request_opts => oidcc_http_util:request_opts(),
    quirks => quirks()
}.

?DOC("""
Record containing OpenID and OAuth 2.0 Configuration.

See:
* https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
* https://datatracker.ietf.org/doc/html/draft-jones-oauth-discovery-01#section-4.1
* https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata

All unrecognized fields are stored in `extra_fields`.
""").
?DOC(#{since => <<"3.0.0">>}).
-type t() ::
    #oidcc_provider_configuration{
        issuer :: uri_string:uri_string(),
        authorization_endpoint :: uri_string:uri_string(),
        token_endpoint :: uri_string:uri_string() | undefined,
        userinfo_endpoint :: uri_string:uri_string() | undefined,
        jwks_uri :: uri_string:uri_string() | undefined,
        registration_endpoint :: uri_string:uri_string() | undefined,
        scopes_supported :: [binary()] | undefined,
        response_types_supported :: [binary()],
        response_modes_supported :: [binary()],
        grant_types_supported :: [binary()],
        acr_values_supported :: [binary()] | undefined,
        subject_types_supported :: [pairwise | public],
        id_token_signing_alg_values_supported :: [binary()],
        id_token_encryption_alg_values_supported ::
            [binary()] | undefined,
        id_token_encryption_enc_values_supported ::
            [binary()] | undefined,
        userinfo_signing_alg_values_supported :: [binary()] | undefined,
        userinfo_encryption_alg_values_supported ::
            [binary()] | undefined,
        userinfo_encryption_enc_values_supported ::
            [binary()] | undefined,
        request_object_signing_alg_values_supported ::
            [binary()] | undefined,
        request_object_encryption_alg_values_supported ::
            [binary()] | undefined,
        request_object_encryption_enc_values_supported ::
            [binary()] | undefined,
        token_endpoint_auth_methods_supported :: [binary()],
        token_endpoint_auth_signing_alg_values_supported ::
            [binary()] | undefined,
        display_values_supported :: [binary()] | undefined,
        claim_types_supported :: [normal | aggregated | distributed],
        claims_supported :: [binary()] | undefined,
        service_documentation :: uri_string:uri_string() | undefined,
        claims_locales_supported :: [binary()] | undefined,
        ui_locales_supported :: [binary()] | undefined,
        claims_parameter_supported :: boolean(),
        request_parameter_supported :: boolean(),
        request_uri_parameter_supported :: boolean(),
        require_request_uri_registration :: boolean(),
        op_policy_uri :: uri_string:uri_string() | undefined,
        op_tos_uri :: uri_string:uri_string() | undefined,
        revocation_endpoint :: uri_string:uri_string() | undefined,
        revocation_endpoint_auth_methods_supported :: [binary()],
        revocation_endpoint_auth_signing_alg_values_supported ::
            [binary()] | undefined,
        introspection_endpoint :: uri_string:uri_string() | undefined,
        introspection_endpoint_auth_methods_supported :: [binary()],
        introspection_endpoint_auth_signing_alg_values_supported ::
            [binary()] | undefined,
        code_challenge_methods_supported :: [binary()] | undefined,
        end_session_endpoint :: uri_string:uri_string() | undefined,
        require_pushed_authorization_requests :: boolean(),
        pushed_authorization_request_endpoint :: uri_string:uri_string() | undefined,
        authorization_signing_alg_values_supported :: [binary()] | undefined,
        authorization_encryption_alg_values_supported :: [binary()] | undefined,
        authorization_encryption_enc_values_supported :: [binary()] | undefined,
        authorization_response_iss_parameter_supported :: boolean(),
        dpop_signing_alg_values_supported :: [binary()] | undefined,
        require_signed_request_object :: boolean(),
        mtls_endpoint_aliases :: #{binary() => uri_string:uri_string()},
        extra_fields :: #{binary() => term()}
    }.

?DOC(#{since => <<"3.0.0">>}).
-type error() ::
    invalid_content_type
    | {issuer_mismatch, Issuer :: binary()}
    | oidcc_decode_util:error()
    | oidcc_http_util:error().

-define(DEFAULT_CONFIG_EXPIRY, timer:minutes(15)).

-telemetry_event(#{
    event => [oidcc, load_configuration, start],
    description => <<"Emitted at the start of loading the provider configuration">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, stop],
    description => <<"Emitted at the end of loading the provider configuration">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, exception],
    description => <<"Emitted at the end of loading the provider configuration">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_jwks, start],
    description => <<"Emitted at the start of loading the provider jwks">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{jwks_uri => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_jwks, stop],
    description => <<"Emitted at the end of loading the provider jwks">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{jwks_uri => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_jwks, exception],
    description => <<"Emitted at the end of loading the provider jwks">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{jwks_uri => uri_string:uri_string()}">>
}).

?DOC("""
Load OpenID Configuration into a `t:oidcc_provider_configuration:t/0` record.

## Examples

```erlang
{ok, #oidcc_provider_configuration{}} =
  oidcc_provider_configuration:load_configuration("https://accounts.google.com").
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec load_configuration(Issuer, Opts) ->
    {ok, {Configuration :: t(), Expiry :: pos_integer()}} | {error, error()}
when
    Issuer :: uri_string:uri_string(),
    Opts :: opts().
load_configuration(Issuer0, Opts) ->
    Issuer = binary:list_to_bin([Issuer0]),
    TelemetryOpts = #{topic => [oidcc, load_configuration], extra_meta => #{issuer => Issuer}},
    RequestOpts = maps:get(request_opts, Opts, #{}),

    RequestUrl = url_join(".well-known/openid-configuration", Issuer),
    Request = {RequestUrl, []},

    Quirks = maps:get(quirks, Opts, #{}),
    % this quirk is deprecated, but we keep the support for backwards compatibility.
    AllowIssuerMismatch = maps:get(allow_issuer_mismatch, Quirks, false),

    DefaultExpiry = maps:get(fallback_expiry, Opts, ?DEFAULT_CONFIG_EXPIRY),

    maybe
        {ok, {{json, ConfigurationMap}, Headers}} ?=
            oidcc_http_util:request(get, Request, TelemetryOpts, RequestOpts),
        Expiry = oidcc_http_util:headers_to_cache_deadline(Headers, DefaultExpiry),
        {ok, #oidcc_provider_configuration{issuer = ConfigIssuer} = Configuration} ?=
            decode_configuration(ConfigurationMap, #{quirks => Quirks}),
        case ConfigIssuer of
            Issuer ->
                {ok, {Configuration, Expiry}};
            _DifferentIssuer when AllowIssuerMismatch -> {ok, {Configuration, Expiry}};
            DifferentIssuer when not AllowIssuerMismatch ->
                {error, {issuer_mismatch, DifferentIssuer}}
        end
    else
        {error, Reason} ->
            {error, Reason};
        {ok, {{_Format, _Body}, _Headers}} ->
            {error, invalid_content_type}
    end.

?DOC("See `load_configuration/2`.").
?DOC(#{since => <<"3.1.0">>}).
-spec load_configuration(Issuer) ->
    {ok, {Configuration :: t(), Expiry :: pos_integer()}} | {error, error()}
when
    Issuer :: uri_string:uri_string().
load_configuration(Issuer) -> load_configuration(Issuer, #{}).

?DOC("""
Load JWKs into a `t:jose_jwk:key/0` record.

## Examples

```erlang
{ok, #jose_jwk{}} =
  oidcc_provider_configuration:load_jwks("https://www.googleapis.com/oauth2/v3/certs").
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec load_jwks(JwksUri, Opts) ->
    {ok, {Jwks :: jose_jwk:key(), Expiry :: pos_integer()}} | {error, term()}
when
    JwksUri :: uri_string:uri_string(),
    Opts :: opts().
load_jwks(JwksUri, Opts) ->
    TelemetryOpts = #{topic => [oidcc, load_jwks], extra_meta => #{jwks_uri => JwksUri}},
    RequestOpts = maps:get(request_opts, Opts, #{}),

    DefaultExpiry = maps:get(fallback_expiry, Opts, ?DEFAULT_CONFIG_EXPIRY),

    maybe
        {ok, {{json, JwksBinary}, Headers}} ?=
            oidcc_http_util:request(get, {JwksUri, []}, TelemetryOpts, RequestOpts),
        Expiry = oidcc_http_util:headers_to_cache_deadline(Headers, DefaultExpiry),
        Jwks = jose_jwk:from(JwksBinary),
        {ok, {Jwks, Expiry}}
    else
        {error, Reason} -> {error, Reason};
        {ok, {{_Format, _Body}, _Headers}} -> {error, invalid_content_type}
    end.

?DOC("""
Decode JSON into a `t:oidcc_provider_configuration:t/0` record.

## Examples

```erlang
{ok, {{"HTTP/1.1",200,"OK"}, _Headers, Body}} =
  httpc:request("https://accounts.google.com/.well-known/openid-configuration"),

{ok, DecodedJson} = your_json_lib:decode(Body),

{ok, #oidcc_provider_configuration{}} =
  oidcc_provider_configuration:decode_configuration(DecodedJson).
```
""").
?DOC(#{since => <<"3.1.0">>}).
-spec decode_configuration(Configuration, Opts) -> {ok, t()} | {error, error()} when
    Configuration :: map(), Opts :: opts().
decode_configuration(Configuration0, Opts) ->
    Quirks = maps:get(quirks, Opts, #{}),
    AllowUnsafeHttp = maps:get(allow_unsafe_http, Quirks, false),

    DocumentOverrides = maps:get(document_overrides, Quirks, #{}),
    Configuration = maps:merge(Configuration0, DocumentOverrides),

    maybe
        {ok, {
            #{
                issuer := Issuer,
                authorization_endpoint := AuthorizationEndpoint,
                authorization_endpoint := AuthorizationEndpoint,
                token_endpoint := TokenEndpoint,
                userinfo_endpoint := UserinfoEndpoint,
                jwks_uri := JwksUri,
                registration_endpoint := RegistrationEndpoint,
                scopes_supported := ScopesSupported,
                response_types_supported := ResponseTypesSupported,
                response_modes_supported := ResponseModesSupported,
                grant_types_supported := GrantTypesSupported,
                acr_values_supported := AcrValuesSupported,
                subject_types_supported := SubjectTypesSupported,
                id_token_signing_alg_values_supported := IdTokenSigningAlgValuesSupported,
                id_token_encryption_alg_values_supported := IdTokenEncryptionAlgValuesSupported,
                id_token_encryption_enc_values_supported := IdTokenEncryptionEncValuesSupported,
                userinfo_signing_alg_values_supported := UserinfoSigningAlgValuesSupported,
                userinfo_encryption_alg_values_supported := UserinfoEncryptionAlgValuesSupported,
                userinfo_encryption_enc_values_supported := UserinfoEncryptionEncValuesSupported,
                request_object_signing_alg_values_supported :=
                    RequestObjectSigningAlgValuesSupported,
                request_object_encryption_alg_values_supported :=
                    RequestObjectEncryptionAlgValuesSupported,
                request_object_encryption_enc_values_supported :=
                    RequestObjectEncryptionEncValuesSupported,
                token_endpoint_auth_methods_supported := TokenEndpointAuthMethodsSupported,
                token_endpoint_auth_signing_alg_values_supported :=
                    TokenEndpointAuthSigningAlgValuesSupported,
                display_values_supported := DisplayValuesSupported,
                claim_types_supported := ClaimTypesSupported,
                claims_supported := ClaimsSupported,
                service_documentation := ServiceDocumentation,
                claims_locales_supported := ClaimsLocalesSupported,
                ui_locales_supported := UiLocalesSupported,
                claims_parameter_supported := ClaimsParameterSupported,
                request_parameter_supported := RequestParameterSupported,
                request_uri_parameter_supported := RequestUriParameterSupported,
                require_request_uri_registration := RequireRequestUriRegistration,
                op_policy_uri := OpPolicyUri,
                op_tos_uri := OpTosUri,
                revocation_endpoint := RevocationEndpoint,
                revocation_endpoint_auth_methods_supported :=
                    RevocationEndpointAuthMethodsSupported,
                revocation_endpoint_auth_signing_alg_values_supported :=
                    RevocationEndpointAuthSigningAlgValuesSupported,
                introspection_endpoint := IntrospectionEndpoint,
                introspection_endpoint_auth_methods_supported :=
                    IntrospectionEndpointAuthMethodsSupported,
                introspection_endpoint_auth_signing_alg_values_supported :=
                    IntrospectionEndpointAuthSigningAlgValuesSupported,
                code_challenge_methods_supported := CodeChallengeMethodsSupported,
                end_session_endpoint := EndSessionEndpoint,
                require_pushed_authorization_requests := RequirePushedAuthorizationRequests,
                pushed_authorization_request_endpoint := PushedAuthorizationRequestEndpoint,
                authorization_signing_alg_values_supported :=
                    AuthorizationSigningAlgValuesSupported,
                authorization_encryption_alg_values_supported :=
                    AuthorizationEncryptionAlgValuesSupported,
                authorization_encryption_enc_values_supported :=
                    AuthorizationEncryptionEncValuesSupported,
                authorization_response_iss_parameter_supported :=
                    AuthorizationResponseIssParameterSupported,
                dpop_signing_alg_values_supported := DpopSigningAlgValuesSupported,
                require_signed_request_object := RequireSignedRequestObject,
                mtls_endpoint_aliases := MtlsEndpointAliases,
                tls_client_certificate_bound_access_tokens := TlsClientCertificateBoundAccessTokens
            },
            ExtraFields
        }} ?=
            oidcc_decode_util:extract(
                Configuration,
                [
                    {required, issuer, fun oidcc_decode_util:parse_setting_uri/2},
                    {required, authorization_endpoint, fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, token_endpoint, undefined,
                        fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, userinfo_endpoint, undefined,
                        case AllowUnsafeHttp of
                            true -> fun oidcc_decode_util:parse_setting_uri/2;
                            false -> fun oidcc_decode_util:parse_setting_uri_https/2
                        end},
                    {required, jwks_uri, fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, registration_endpoint, undefined,
                        fun oidcc_decode_util:parse_setting_uri/2},
                    {required, scopes_supported, fun parse_scopes_supported/2},
                    {required, response_types_supported,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, response_modes_supported, [<<"query">>, <<"fragment">>],
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, grant_types_supported, [<<"authorization_code">>, <<"implicit">>],
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, acr_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {required, subject_types_supported, fun parse_subject_types_supported/2},
                    {required, id_token_signing_alg_values_supported,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, id_token_encryption_alg_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, id_token_encryption_enc_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, userinfo_signing_alg_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, userinfo_encryption_alg_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, userinfo_encryption_enc_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, request_object_signing_alg_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, request_object_encryption_alg_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, request_object_encryption_enc_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, token_endpoint_auth_methods_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, token_endpoint_auth_signing_alg_values_supported, undefined,
                        fun parse_token_signing_alg_values_no_none/2},
                    {optional, display_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, claim_types_supported, [normal], fun parse_claim_types_supported/2},
                    {optional, claims_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, service_documentation, undefined,
                        fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, claims_locales_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, ui_locales_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, claims_parameter_supported, false,
                        fun oidcc_decode_util:parse_setting_boolean/2},
                    {optional, request_parameter_supported, false,
                        fun oidcc_decode_util:parse_setting_boolean/2},
                    {optional, request_uri_parameter_supported, true,
                        fun oidcc_decode_util:parse_setting_boolean/2},
                    {optional, require_request_uri_registration, false,
                        fun oidcc_decode_util:parse_setting_boolean/2},
                    {optional, op_policy_uri, undefined, fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, op_tos_uri, undefined, fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, revocation_endpoint, undefined,
                        fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, revocation_endpoint_auth_methods_supported,
                        [<<"client_secret_basic">>],
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, revocation_endpoint_auth_signing_alg_values_supported, undefined,
                        fun parse_token_signing_alg_values_no_none/2},
                    {optional, introspection_endpoint, undefined,
                        fun oidcc_decode_util:parse_setting_uri/2},
                    {optional, introspection_endpoint_auth_methods_supported,
                        [<<"client_secret_basic">>],
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, introspection_endpoint_auth_signing_alg_values_supported, undefined,
                        fun parse_token_signing_alg_values_no_none/2},
                    {optional, code_challenge_methods_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, end_session_endpoint, undefined,
                        case AllowUnsafeHttp of
                            true -> fun oidcc_decode_util:parse_setting_uri/2;
                            false -> fun oidcc_decode_util:parse_setting_uri_https/2
                        end},
                    {optional, require_pushed_authorization_requests, false,
                        fun oidcc_decode_util:parse_setting_boolean/2},
                    {optional, pushed_authorization_request_endpoint, undefined,
                        case AllowUnsafeHttp of
                            true -> fun oidcc_decode_util:parse_setting_uri/2;
                            false -> fun oidcc_decode_util:parse_setting_uri_https/2
                        end},
                    {optional, authorization_signing_alg_values_supported, undefined,
                        fun parse_token_signing_alg_values_no_none/2},
                    {optional, authorization_encryption_alg_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, authorization_encryption_enc_values_supported, undefined,
                        fun oidcc_decode_util:parse_setting_binary_list/2},
                    {optional, authorization_response_iss_parameter_supported, false,
                        fun oidcc_decode_util:parse_setting_boolean/2},
                    {optional, dpop_signing_alg_values_supported, undefined,
                        fun parse_token_signing_alg_values_no_none/2},
                    {optional, require_signed_request_object, false,
                        fun oidcc_decode_util:parse_setting_boolean/2},
                    {optional, mtls_endpoint_aliases, #{},
                        case AllowUnsafeHttp of
                            true -> fun oidcc_decode_util:parse_setting_uri_map/2;
                            false -> fun oidcc_decode_util:parse_setting_uri_https_map/2
                        end},
                    {optional, tls_client_certificate_bound_access_tokens, false,
                        fun oidcc_decode_util:parse_setting_boolean/2}
                ],
                #{}
            ),
        {ok, #oidcc_provider_configuration{
            issuer = Issuer,
            authorization_endpoint = AuthorizationEndpoint,
            token_endpoint = TokenEndpoint,
            userinfo_endpoint = UserinfoEndpoint,
            jwks_uri = JwksUri,
            registration_endpoint = RegistrationEndpoint,
            scopes_supported = ScopesSupported,
            response_types_supported = ResponseTypesSupported,
            response_modes_supported = ResponseModesSupported,
            grant_types_supported = GrantTypesSupported,
            acr_values_supported = AcrValuesSupported,
            subject_types_supported = SubjectTypesSupported,
            id_token_signing_alg_values_supported =
                IdTokenSigningAlgValuesSupported,
            id_token_encryption_alg_values_supported =
                IdTokenEncryptionAlgValuesSupported,
            id_token_encryption_enc_values_supported =
                IdTokenEncryptionEncValuesSupported,
            userinfo_signing_alg_values_supported =
                UserinfoSigningAlgValuesSupported,
            userinfo_encryption_alg_values_supported =
                UserinfoEncryptionAlgValuesSupported,
            userinfo_encryption_enc_values_supported =
                UserinfoEncryptionEncValuesSupported,
            request_object_signing_alg_values_supported =
                RequestObjectSigningAlgValuesSupported,
            request_object_encryption_alg_values_supported =
                RequestObjectEncryptionAlgValuesSupported,
            request_object_encryption_enc_values_supported =
                RequestObjectEncryptionEncValuesSupported,
            token_endpoint_auth_methods_supported =
                TokenEndpointAuthMethodsSupported,
            token_endpoint_auth_signing_alg_values_supported =
                TokenEndpointAuthSigningAlgValuesSupported,
            display_values_supported = DisplayValuesSupported,
            claim_types_supported = ClaimTypesSupported,
            claims_supported = ClaimsSupported,
            service_documentation = ServiceDocumentation,
            claims_locales_supported = ClaimsLocalesSupported,
            ui_locales_supported = UiLocalesSupported,
            claims_parameter_supported = ClaimsParameterSupported,
            request_parameter_supported = RequestParameterSupported,
            request_uri_parameter_supported =
                RequestUriParameterSupported,
            require_request_uri_registration =
                RequireRequestUriRegistration,
            op_policy_uri = OpPolicyUri,
            op_tos_uri = OpTosUri,
            revocation_endpoint = RevocationEndpoint,
            revocation_endpoint_auth_methods_supported =
                RevocationEndpointAuthMethodsSupported,
            revocation_endpoint_auth_signing_alg_values_supported =
                RevocationEndpointAuthSigningAlgValuesSupported,
            introspection_endpoint = IntrospectionEndpoint,
            introspection_endpoint_auth_methods_supported =
                IntrospectionEndpointAuthMethodsSupported,
            introspection_endpoint_auth_signing_alg_values_supported =
                IntrospectionEndpointAuthSigningAlgValuesSupported,
            code_challenge_methods_supported =
                CodeChallengeMethodsSupported,
            end_session_endpoint = EndSessionEndpoint,
            require_pushed_authorization_requests = RequirePushedAuthorizationRequests,
            pushed_authorization_request_endpoint = PushedAuthorizationRequestEndpoint,
            authorization_signing_alg_values_supported = AuthorizationSigningAlgValuesSupported,
            authorization_encryption_alg_values_supported =
                AuthorizationEncryptionAlgValuesSupported,
            authorization_encryption_enc_values_supported =
                AuthorizationEncryptionEncValuesSupported,
            authorization_response_iss_parameter_supported =
                AuthorizationResponseIssParameterSupported,
            dpop_signing_alg_values_supported = DpopSigningAlgValuesSupported,
            require_signed_request_object = RequireSignedRequestObject,
            mtls_endpoint_aliases = MtlsEndpointAliases,
            tls_client_certificate_bound_access_tokens = TlsClientCertificateBoundAccessTokens,
            extra_fields = ExtraFields
        }}
    end.

?DOC("See `decode_configuration/2`.").
?DOC(#{since => <<"3.0.0">>}).
-spec decode_configuration(Configuration) -> {ok, t()} | {error, error()} when
    Configuration :: map().
decode_configuration(Configuration) -> decode_configuration(Configuration, #{}).

-spec parse_scopes_supported(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_scopes_supported(Setting, Field) ->
    case oidcc_decode_util:parse_setting_binary_list(Setting, Field) of
        {ok, Scopes} ->
            case lists:member(<<"openid">>, Scopes) of
                true ->
                    {ok, Scopes};
                false ->
                    {error, {invalid_config_property, {scopes_including_openid, Field}}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_subject_types_supported(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_subject_types_supported(Setting, Field) ->
    oidcc_decode_util:parse_setting_list_enum(
        Setting,
        Field,
        fun
            (<<"pairwise">>) ->
                {ok, pairwise};
            (<<"public">>) ->
                {ok, public};
            (_SubjectType) ->
                error
        end
    ).

-spec parse_token_signing_alg_values_no_none(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_token_signing_alg_values_no_none(Setting, Field) ->
    case oidcc_decode_util:parse_setting_binary_list(Setting, Field) of
        {ok, SigningAlgValues} ->
            case
                lists:any(
                    fun
                        (<<"none">>) ->
                            true;
                        (_) ->
                            false
                    end,
                    SigningAlgValues
                )
            of
                false ->
                    {ok, SigningAlgValues};
                true ->
                    {error, {invalid_config_property, {alg_no_none, Field}}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_claim_types_supported(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_claim_types_supported(Setting, Field) ->
    oidcc_decode_util:parse_setting_list_enum(
        Setting,
        Field,
        fun
            (<<"normal">>) ->
                {ok, normal};
            (<<"aggregated">>) ->
                {ok, aggregated};
            (<<"distributed">>) ->
                {ok, distributed};
            (_ClaimType) ->
                error
        end
    ).

-spec url_join(RefURI :: uri_string:uri_string(), BaseURI :: uri_string:uri_string()) ->
    uri_string:uri_string().
url_join(RefURI, BaseURI) ->
    BaseURIBinary = iolist_to_binary(BaseURI),
    case binary_part(BaseURIBinary, byte_size(BaseURIBinary) - 1, 1) of
        <<"/">> -> uri_string:resolve(RefURI, BaseURI);
        _ -> uri_string:resolve(RefURI, [BaseURI, "/"])
    end.
