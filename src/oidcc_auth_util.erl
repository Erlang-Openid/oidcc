%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_auth_util).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("Authentication Utilities").
?MODULEDOC(#{since => <<"3.2.0">>}).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-include_lib("jose/include/jose_jwk.hrl").

-export_type([auth_method/0, error/0]).

?DOC(#{since => <<"3.2.0">>}).
-type auth_method() ::
    none
    | client_secret_basic
    | client_secret_post
    | client_secret_jwt
    | private_key_jwt
    | tls_client_auth.

?DOC(#{since => <<"3.2.0">>}).
-type error() :: no_supported_auth_method.

-export([add_client_authentication/6]).
-export([add_dpop_proof_header/5]).
-export([add_authorization_header/6]).
-export([maybe_mtls_endpoint/4]).

?DOC(false).
-spec add_client_authentication(
    QueryList, Header, SupportedAuthMethods, AllowAlgorithms, Opts, ClientContext
) ->
    {ok, {oidcc_http_util:query_params(), [oidcc_http_util:http_header()]}, auth_method()}
    | {error, error()}
when
    QueryList :: oidcc_http_util:query_params(),
    Header :: [oidcc_http_util:http_header()],
    SupportedAuthMethods :: [binary()] | undefined,
    AllowAlgorithms :: [binary()] | undefined,
    Opts :: map(),
    ClientContext :: oidcc_client_context:t().
add_client_authentication(_QueryList, _Header, undefined, _AllowAlgs, _Opts, _ClientContext) ->
    {error, no_supported_auth_method};
add_client_authentication(
    QueryList0, Header0, SupportedAuthMethods, AllowAlgorithms, Opts, ClientContext
) ->
    PreferredAuthMethods = maps:get(preferred_auth_methods, Opts, [
        private_key_jwt,
        tls_client_auth,
        client_secret_jwt,
        client_secret_post,
        client_secret_basic,
        none
    ]),
    case select_preferred_auth(PreferredAuthMethods, SupportedAuthMethods) of
        {ok, AuthMethod} ->
            case
                add_authentication(
                    QueryList0, Header0, AuthMethod, AllowAlgorithms, Opts, ClientContext
                )
            of
                {ok, {QueryList, Header}} ->
                    {ok, {QueryList, Header}, AuthMethod};
                {error, _} ->
                    add_client_authentication(
                        QueryList0,
                        Header0,
                        SupportedAuthMethods -- [atom_to_binary(AuthMethod)],
                        AllowAlgorithms,
                        Opts,
                        ClientContext
                    )
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec add_authentication(
    QueryList,
    Header,
    AuthMethod,
    AllowAlgorithms,
    Opts,
    ClientContext
) ->
    {ok, {oidcc_http_util:query_params(), [oidcc_http_util:http_header()]}}
    | {error, auth_method_not_possible}
when
    QueryList :: oidcc_http_util:query_params(),
    Header :: [oidcc_http_util:http_header()],
    AuthMethod :: auth_method(),
    AllowAlgorithms :: [binary()] | undefined,
    Opts :: map(),
    ClientContext :: oidcc_client_context:t().
add_authentication(
    QsBodyList,
    Header,
    none,
    _AllowArgs,
    _Opts,
    #oidcc_client_context{client_id = ClientId}
) ->
    NewBodyList = [{<<"client_id">>, ClientId} | QsBodyList],
    {ok, {NewBodyList, Header}};
add_authentication(
    _QsBodyList,
    _Header,
    _Method,
    _AllowAlgs,
    _Opts,
    #oidcc_client_context{client_secret = unauthenticated}
) ->
    {error, auth_method_not_possible};
add_authentication(
    QsBodyList,
    Header,
    client_secret_basic,
    _AllowAlgs,
    _Opts,
    #oidcc_client_context{client_id = ClientId, client_secret = ClientSecret}
) ->
    NewHeader = [oidcc_http_util:basic_auth_header(ClientId, ClientSecret) | Header],
    {ok, {QsBodyList, NewHeader}};
add_authentication(
    QsBodyList,
    Header,
    client_secret_post,
    _AllowAlgs,
    _Opts,
    #oidcc_client_context{client_id = ClientId, client_secret = ClientSecret}
) ->
    NewBodyList =
        [{<<"client_id">>, ClientId}, {<<"client_secret">>, ClientSecret} | QsBodyList],
    {ok, {NewBodyList, Header}};
add_authentication(
    QsBodyList,
    Header,
    client_secret_jwt,
    AllowAlgorithms,
    Opts,
    ClientContext
) ->
    #oidcc_client_context{
        client_secret = ClientSecret
    } = ClientContext,

    maybe
        [_ | _] ?= AllowAlgorithms,
        #jose_jwk{} =
            OctJwk ?=
                oidcc_jwt_util:client_secret_oct_keys(
                    AllowAlgorithms,
                    ClientSecret
                ),
        {ok, ClientAssertion} ?=
            signed_client_assertion(
                AllowAlgorithms,
                Opts,
                ClientContext,
                OctJwk
            ),
        {ok, add_jwt_bearer_assertion(ClientAssertion, QsBodyList, Header, ClientContext)}
    else
        _ ->
            {error, auth_method_not_possible}
    end;
add_authentication(
    QsBodyList,
    Header,
    private_key_jwt,
    AllowAlgorithms,
    Opts,
    ClientContext
) ->
    #oidcc_client_context{
        client_jwks = ClientJwks
    } = ClientContext,

    maybe
        [_ | _] ?= AllowAlgorithms,
        #jose_jwk{} ?= ClientJwks,
        {ok, ClientAssertion} ?=
            signed_client_assertion(AllowAlgorithms, Opts, ClientContext, ClientJwks),
        {ok, add_jwt_bearer_assertion(ClientAssertion, QsBodyList, Header, ClientContext)}
    else
        _ ->
            {error, auth_method_not_possible}
    end;
add_authentication(
    QsBodyList,
    Header,
    tls_client_auth,
    _AllowAlgorithms,
    Opts,
    #oidcc_client_context{client_id = ClientId}
) ->
    case Opts of
        #{request_opts := #{ssl := _}} ->
            %% only supported if custom SSL params are provided
            NewBodyList = [{<<"client_id">>, ClientId} | QsBodyList],
            {ok, {NewBodyList, Header}};
        _ ->
            {error, auth_method_not_possible}
    end.

-spec select_preferred_auth(PreferredAuthMethods, AuthMethodsSupported) ->
    {ok, auth_method()} | {error, error()}
when
    PreferredAuthMethods :: [auth_method(), ...],
    AuthMethodsSupported :: [binary()].
select_preferred_auth(PreferredAuthMethods, AuthMethodsSupported) ->
    PreferredAuthMethodSearchFun = fun(AuthMethod) ->
        lists:member(atom_to_binary(AuthMethod), AuthMethodsSupported)
    end,

    case lists:search(PreferredAuthMethodSearchFun, PreferredAuthMethods) of
        {value, AuthMethod} ->
            {ok, AuthMethod};
        false ->
            {error, no_supported_auth_method}
    end.

-spec signed_client_assertion(AllowAlgorithms, Opts, ClientContext, Jwk) ->
    {ok, binary()} | {error, term()}
when
    AllowAlgorithms :: [binary()],
    Jwk :: jose_jwk:key(),
    Opts :: map(),
    ClientContext :: oidcc_client_context:t().
signed_client_assertion(AllowAlgorithms, Opts, ClientContext, Jwk) ->
    Jwt = jose_jwt:from(token_request_claims(Opts, ClientContext)),

    oidcc_jwt_util:sign(Jwt, Jwk, AllowAlgorithms).

-spec token_request_claims(Opts, ClientContext) -> oidcc_jwt_util:claims() when
    Opts :: map(),
    ClientContext :: oidcc_client_context:t().
token_request_claims(Opts, #oidcc_client_context{
    client_id = ClientId,
    provider_configuration = #oidcc_provider_configuration{issuer = Issuer}
}) ->
    Audience = maps:get(audience, Opts, Issuer),
    MaxClockSkew =
        case application:get_env(oidcc, max_clock_skew) of
            undefined -> 0;
            {ok, ClockSkew} -> ClockSkew
        end,

    maps:merge(
        #{
            <<"iss">> => ClientId,
            <<"sub">> => ClientId,
            <<"aud">> => Audience,
            <<"jti">> => random_string(32),
            <<"iat">> => os:system_time(seconds),
            <<"exp">> => os:system_time(seconds) + 30,
            <<"nbf">> => os:system_time(seconds) - MaxClockSkew
        },
        maps:get(token_request_claims, Opts, #{})
    ).

-spec add_jwt_bearer_assertion(ClientAssertion, Body, Header, ClientContext) -> {Body, Header} when
    ClientAssertion :: binary(),
    Body :: oidcc_http_util:query_params(),
    Header :: [oidcc_http_util:http_header()],
    ClientContext :: oidcc_client_context:t().
add_jwt_bearer_assertion(ClientAssertion, Body, Header, ClientContext) ->
    #oidcc_client_context{client_id = ClientId} = ClientContext,
    {
        [
            {<<"client_assertion_type">>,
                <<"urn:ietf:params:oauth:client-assertion-type:jwt-bearer">>},
            {<<"client_assertion">>, ClientAssertion},
            {<<"client_id">>, ClientId}
            | Body
        ],
        Header
    }.

?DOC(false).
-spec add_dpop_proof_header(Header, Method, Endpoint, Opts, ClientContext) -> Header when
    Header :: [oidcc_http_util:http_header()],
    Method :: post | get,
    Endpoint :: uri_string:uri_string(),
    Opts :: #{nonce => binary()},
    ClientContext :: oidcc_client_context:t().
add_dpop_proof_header(Header, Method, Endpoint, Opts, ClientContext) ->
    Claims =
        case Opts of
            #{nonce := Nonce} ->
                #{<<"nonce">> => Nonce};
            _ ->
                #{}
        end,
    case dpop_proof(Method, Endpoint, Claims, ClientContext) of
        {ok, SignedRequestObject} ->
            [{"dpop", SignedRequestObject} | Header];
        error ->
            Header
    end.

?DOC(false).
-spec add_authorization_header(
    AccessToken, AccessTokenType, Method, Endpoint, Opts, ClientContext
) ->
    Header
when
    AccessToken :: binary(),
    AccessTokenType :: binary(),
    Method :: post | get,
    Endpoint :: uri_string:uri_string(),
    Opts :: #{dpop_nonce => binary()},
    ClientContext :: oidcc_client_context:t(),
    Header :: [oidcc_http_util:http_header()].
add_authorization_header(
    AccessToken, AccessTokenType, Method, Endpoint, Opts, ClientContext
) ->
    maybe
        true ?= string:casefold(<<"dpop">>) =:= string:casefold(AccessTokenType),
        Claims0 =
            case Opts of
                #{dpop_nonce := Nonce} ->
                    #{<<"nonce">> => Nonce};
                _ ->
                    #{}
            end,
        Claims = Claims0#{
            <<"ath">> => base64:encode(crypto:hash(sha256, AccessToken), #{
                mode => urlsafe, padding => false
            })
        },
        {ok, SignedRequestObject} ?= dpop_proof(Method, Endpoint, Claims, ClientContext),
        [
            {"authorization", [AccessTokenType, <<" ">>, AccessToken]},
            {"dpop", SignedRequestObject}
        ]
    else
        _ ->
            [oidcc_http_util:bearer_auth_header(AccessToken)]
    end.

?DOC(false).
-spec maybe_mtls_endpoint(
    Endpoint, auth_method(), MtlsEndpointName, ClientContext
) -> Endpoint when
    Endpoint :: uri_string:uri_string(),
    MtlsEndpointName :: binary(),
    ClientContext :: oidcc_client_context:t().
maybe_mtls_endpoint(Endpoint, tls_client_auth, MtlsEndpointName, ClientContext) ->
    case
        ClientContext#oidcc_client_context.provider_configuration#oidcc_provider_configuration.mtls_endpoint_aliases
    of
        #{MtlsEndpointName := MtlsEndpoint} ->
            MtlsEndpoint;
        _ ->
            Endpoint
    end;
maybe_mtls_endpoint(Endpoint, _AuthMethod, _EndpointName, _ClientContext) ->
    Endpoint.

-spec dpop_proof(Method, Endpoint, Claims, ClientContext) -> {ok, binary()} | error when
    Method :: post | get,
    Endpoint :: uri_string:uri_string(),
    Claims :: map(),
    ClientContext :: oidcc_client_context:t().
dpop_proof(Method, Endpoint, Claims0, #oidcc_client_context{
    client_jwks = #jose_jwk{} = ClientJwks,
    provider_configuration = #oidcc_provider_configuration{
        dpop_signing_alg_values_supported = [_ | _] = SigningAlgSupported
    }
}) ->
    MaxClockSkew =
        case application:get_env(oidcc, max_clock_skew) of
            undefined -> 0;
            {ok, ClockSkew} -> ClockSkew
        end,
    HtmClaim = string:uppercase(atom_to_binary(Method, utf8)),
    Claims = Claims0#{
        <<"jti">> => random_string(32),
        <<"htm">> => HtmClaim,
        <<"htu">> => iolist_to_binary(Endpoint),
        <<"iat">> => os:system_time(seconds),
        <<"exp">> => os:system_time(seconds) + 30,
        <<"nbf">> => os:system_time(seconds) - MaxClockSkew
    },
    Jwt = jose_jwt:from(Claims),

    oidcc_jwt_util:sign_dpop(Jwt, ClientJwks, SigningAlgSupported);
dpop_proof(_Method, _Endpoint, _Claims, _ClientContext) ->
    error.

-spec random_string(Bytes :: pos_integer()) -> binary().
random_string(Bytes) ->
    base64:encode(crypto:strong_rand_bytes(Bytes), #{mode => urlsafe, padding => false}).
