%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_client_registration).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("""
Dynamic Client Registration Utilities.

See https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata.

## Records

To use the record, import the definition:

```erlang
-include_lib(["oidcc/include/oidcc_client_registration.hrl"]).
```

## Telemetry

See [`Oidcc.ClientRegistration`](`m:'Elixir.Oidcc.ClientRegistration'`).
""").
?MODULEDOC(#{since => <<"3.0.0">>}).

-include("oidcc_client_registration.hrl").
-include("oidcc_provider_configuration.hrl").

-export([register/3]).

-export_type([error/0]).
-export_type([opts/0]).
-export_type([response/0]).
-export_type([t/0]).

?DOC("""
Configure configuration loading / parsing.

## Parameters

* `initial_access_token` - Access Token for registration
* `request_opts` - config for HTTP request
""").
?DOC(#{since => <<"3.0.0">>}).
-type opts() :: #{
    initial_access_token => binary() | undefined,
    request_opts => oidcc_http_util:request_opts()
}.

?DOC("""
Record containing Client Registration Metadata.

See https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata and
https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata.

All unrecognized fields are stored in `extra_fields`.
""").
?DOC(#{since => <<"3.0.0">>}).
-type t() ::
    #oidcc_client_registration{
        %% OpenID Connect Dynamic Client Registration 1.0
        redirect_uris :: [uri_string:uri_string()],
        %% OpenID Connect Dynamic Client Registration 1.0
        response_types :: [binary()] | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        grant_types :: [binary()] | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        application_type :: web | native,
        %% OpenID Connect Dynamic Client Registration 1.0
        contacts :: [binary()] | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        client_name :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        logo_uri :: uri_string:uri_string() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        client_uri :: uri_string:uri_string() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        policy_uri :: uri_string:uri_string() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        tos_uri :: uri_string:uri_string() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        jwks :: jose_jwk:key() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        jwks_uri :: uri_string:uri_string() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        sector_identifier_uri :: uri_string:uri_string() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        subject_type :: pairwise | public | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        id_token_signed_response_alg :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        id_token_encrypted_response_alg :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        id_token_encrypted_response_enc :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        userinfo_signed_response_alg :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        userinfo_encrypted_response_alg :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        userinfo_encrypted_response_enc :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        request_object_signing_alg :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        request_object_encryption_alg :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        request_object_encryption_enc :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        token_endpoint_auth_method :: erlang:binary(),
        %% OpenID Connect Dynamic Client Registration 1.0
        token_endpoint_auth_signing_alg :: binary() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        default_max_age :: pos_integer() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        require_auth_time :: boolean(),
        %% OpenID Connect Dynamic Client Registration 1.0
        default_acr_values :: [binary()] | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        initiate_login_uri :: uri_string:uri_string() | undefined,
        %% OpenID Connect Dynamic Client Registration 1.0
        request_uris :: [uri_string:uri_string()] | undefined,
        %% OpenID Connect RP-Initiated Logout 1.0
        post_logout_redirect_uris :: [uri_string:uri_string()] | undefined,
        %% OAuth 2.0 Pushed Authorization Requests
        require_pushed_authorization_requests :: boolean(),
        %% OAuth 2.0 Demonstrating Proof of Possession (DPoP)
        dpop_bound_access_tokens :: boolean(),
        %% Unknown Fields
        extra_fields :: #{binary() => term()}
    }.

?DOC("""
Record containing Client Registration Response.

See https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse.

All unrecognized fields are stored in `extra_fields`.
""").
?DOC(#{since => <<"3.0.0">>}).
-type response() ::
    #oidcc_client_registration_response{
        client_id :: erlang:binary(),
        client_secret :: binary() | undefined,
        registration_access_token :: binary() | undefined,
        registration_client_uri :: uri_string:uri_string() | undefined,
        client_id_issued_at :: pos_integer() | undefined,
        client_secret_expires_at :: pos_integer() | undefined,
        %% Unknown Fields
        extra_fields :: #{binary() => term()}
    }.

?DOC(#{since => <<"3.0.0">>}).
-type error() ::
    registration_not_supported
    | invalid_content_type
    | oidcc_decode_util:error()
    | oidcc_http_util:error().

-telemetry_event(#{
    event => [oidcc, register_client, start],
    description => <<"Emitted at the start of registering the client">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, register_client, stop],
    description => <<"Emitted at the end of registering the client">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, register_client, exception],
    description => <<"Emitted at the end of registering the client">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

?DOC("""
Register Client.

## Examples

```erlang
{ok, ProviderConfiguration} =
  oidcc_provider_configuration:load_configuration("https://your.issuer"),

{ok, #oidcc_client_registration_response{
  client_id = ClientId,
  client_secret = ClientSecret
}} =
  oidcc_client_registration:register(
    ProviderConfiguration,
    #oidcc_client_registration{
      redirect_uris = ["https://your.application.com/oidcc/callback"]
    },
    #{initial_access_token => <<"optional token you got from the provider">>}
  ).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec register(ProviderConfiguration, Registration, Opts) ->
    {ok, response()} | {error, error()}
when
    ProviderConfiguration :: oidcc_provider_configuration:t(),
    Registration :: t(),
    Opts :: opts().
register(#oidcc_provider_configuration{registration_endpoint = undefined}, _Registration, _Opts) ->
    {error, registration_not_supported};
register(
    #oidcc_provider_configuration{issuer = Issuer, registration_endpoint = RegistrationEndpoint},
    Registration,
    Opts
) ->
    RegistrationBody = encode(Registration),
    TelemetryOpts = #{topic => [oidcc, register_client], extra_meta => #{issuer => Issuer}},
    RequestOpts = maps:get(request_opts, Opts, #{}),
    Headers =
        case maps:get(initial_access_token, Opts, undefined) of
            undefined -> [];
            Token -> [{"authorization", ["Bearer ", Token]}]
        end,
    Request = {RegistrationEndpoint, Headers, "application/json", RegistrationBody},

    maybe
        {ok, {{json, ResponseMap}, _Headers}} ?=
            oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
        {ok, #oidcc_client_registration_response{} = Response} ?= decode_response(ResponseMap),
        {ok, Response}
    else
        {error, Reason} -> {error, Reason};
        {ok, {{_Format, _Body}, _}} -> {error, invalid_content_type}
    end.

-spec decode_response(Response) -> {ok, response()} | {error, error()} when Response :: map().
decode_response(Response) ->
    case
        oidcc_decode_util:extract(
            Response,
            [
                {required, client_id, fun oidcc_decode_util:parse_setting_binary/2},
                {optional, client_secret, undefined, fun oidcc_decode_util:parse_setting_binary/2},
                {optional, registration_access_token, undefined,
                    fun oidcc_decode_util:parse_setting_binary/2},
                {optional, registration_client_uri, undefined,
                    fun oidcc_decode_util:parse_setting_uri_https/2},
                {optional, client_id_issued_at, undefined,
                    fun oidcc_decode_util:parse_setting_number/2},
                {optional, client_secret_expires_at, undefined,
                    fun oidcc_decode_util:parse_setting_number/2}
            ],
            #{}
        )
    of
        {ok, {
            #{
                client_id := ClientId,
                client_secret := ClientSecret,
                registration_access_token := RegistrationAccessToken,
                registration_client_uri := RegistrationClientUri,
                client_id_issued_at := ClientIdIssuedAt,
                client_secret_expires_at := ClientSecretExpiresAt
            },
            ExtraFields
        }} ->
            {ok, #oidcc_client_registration_response{
                client_id = ClientId,
                client_secret = ClientSecret,
                registration_access_token = RegistrationAccessToken,
                registration_client_uri = RegistrationClientUri,
                client_id_issued_at = ClientIdIssuedAt,
                client_secret_expires_at = ClientSecretExpiresAt,
                extra_fields = ExtraFields
            }};
        {error, Reason} ->
            {error, Reason}
    end.

-spec encode(Metadata) -> binary() when Metadata :: t().
encode(#oidcc_client_registration{
    redirect_uris = RedirectUris,
    response_types = ResponseTypes,
    grant_types = GrantTypes,
    application_type = ApplicationType,
    contacts = Contacts,
    client_name = ClientName,
    logo_uri = LogoUri,
    client_uri = ClientUri,
    policy_uri = PolicyUri,
    tos_uri = TosUri,
    jwks = Jwks,
    sector_identifier_uri = SectorIdentifierUri,
    subject_type = SubjectType,
    id_token_signed_response_alg = IdTokenSignedResponseAlg,
    id_token_encrypted_response_alg = IdTokenencryptedResponseAlg,
    id_token_encrypted_response_enc = IdTokenEncryptedResponseEnc,
    userinfo_signed_response_alg = UserinfoSignedResponseAlg,
    userinfo_encrypted_response_alg = UserinfoEncryptedResponseAlg,
    userinfo_encrypted_response_enc = UserinfoEncryptedResponseEnc,
    request_object_signing_alg = RequestObjectSigningAlg,
    request_object_encryption_alg = RequestObjectEncryptionAlg,
    request_object_encryption_enc = RequestObjectEncryptionEnc,
    token_endpoint_auth_method = TokenEndpointAuthMethod,
    token_endpoint_auth_signing_alg = TokenEndpointAuthSigningAlg,
    default_max_age = DefaultMaxAge,
    require_auth_time = RequireAuthTime,
    default_acr_values = DefaultAcrValues,
    initiate_login_uri = InitiateLoginUri,
    request_uris = RequestUris,
    post_logout_redirect_uris = PostLogoutRedirectUris,
    require_pushed_authorization_requests = RequirePushedAuthorizationRequests,
    extra_fields = ExtraFields
}) ->
    Map0 = #{
        redirect_uris => RedirectUris,
        response_types => ResponseTypes,
        grant_types => GrantTypes,
        application_type => ApplicationType,
        contacts => Contacts,
        client_name => ClientName,
        logo_uri => LogoUri,
        client_uri => ClientUri,
        policy_uri => PolicyUri,
        tos_uri => TosUri,
        jwks =>
            case Jwks of
                undefined ->
                    undefined;
                _ ->
                    {_KeyType, KeyMap} = jose_jwk:to_map(Jwks),
                    KeyMap
            end,
        sector_identifier_uri => SectorIdentifierUri,
        subject_type => SubjectType,
        id_token_signed_response_alg => IdTokenSignedResponseAlg,
        id_token_encrypted_response_alg => IdTokenencryptedResponseAlg,
        id_token_encrypted_response_enc => IdTokenEncryptedResponseEnc,
        userinfo_signed_response_alg => UserinfoSignedResponseAlg,
        userinfo_encrypted_response_alg => UserinfoEncryptedResponseAlg,
        userinfo_encrypted_response_enc => UserinfoEncryptedResponseEnc,
        request_object_signing_alg => RequestObjectSigningAlg,
        request_object_encryption_alg => RequestObjectEncryptionAlg,
        request_object_encryption_enc => RequestObjectEncryptionEnc,
        token_endpoint_auth_method => TokenEndpointAuthMethod,
        token_endpoint_auth_signing_alg => TokenEndpointAuthSigningAlg,
        default_max_age => DefaultMaxAge,
        require_auth_time => RequireAuthTime,
        default_acr_values => DefaultAcrValues,
        initiate_login_uri => InitiateLoginUri,
        request_uris => RequestUris,
        post_logout_redirect_uris => PostLogoutRedirectUris,
        require_pushed_authorization_requests => RequirePushedAuthorizationRequests
    },
    Map1 = maps:merge(Map0, ExtraFields),
    Map = maps:filter(
        fun
            (_Key, undefined) -> false;
            (_Key, _Value) -> true
        end,
        Map1
    ),
    jose:encode(Map).
