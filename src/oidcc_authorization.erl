%%%-------------------------------------------------------------------
%% @doc Functions to start an OpenID Connect Authorization
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_authorization).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-include_lib("jose/include/jose_jwk.hrl").

-export([create_redirect_url/2]).

-export_type([error/0]).
-export_type([opts/0]).

-type opts() ::
    #{
        scopes => oidcc_scope:scopes(),
        state => binary(),
        nonce => binary(),
        pkce_verifier => binary(),
        require_pkce => boolean(),
        redirect_uri => uri_string:uri_string(),
        url_extension => oidcc_http_util:query_params()
    }.
%% Configure authorization redirect url
%%
%% See [https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest]
%%
%% <h2>Parameters</h2>
%%
%% <ul>
%%   <li>`scopes' - list of scopes to request (defaults to `[<<"openid">>]')</li>
%%   <li>`state' - state to pass to the provider</li>
%%   <li>`nonce' - nonce to pass to the provider</li>
%%   <li>`pkce_verifier' - pkce verifier (random string), see
%%     [https://datatracker.ietf.org/doc/html/rfc7636#section-4.1]</li>
%%   <li>`require_pkce' - whether to require PKCE when getting the token</li>
%%   <li>`redirect_uri' - redirect target after authorization is completed</li>
%%   <li>`url_extension' - add custom query parameters to the authorization url</li>
%% </ul>

-type error() ::
    {grant_type_not_supported, authorization_code}
    | par_required
    | request_object_required
    | pkce_verifier_required
    | no_supported_code_challenge
    | oidcc_http_util:error().

%% @doc
%% Create Auth Redirect URL
%%
%% For a high level interface using {@link oidcc_provider_configuration_worker}
%% see {@link oidcc:create_redirect_url/4}.
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, ClientContext} =
%%     oidcc_client_context:from_configuration_worker(provider_name,
%%                                                    <<"client_id">>,
%%                                                    <<"client_secret">>),
%%
%% {ok, RedirectUri} =
%%     oidcc_authorization:create_redirect_url(ClientContext,
%%                                             #{redirect_uri: <<"https://my.server/return"}),
%%
%% %% RedirectUri = https://my.provider/auth?scope=openid&response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fmy.server%2Freturn
%% '''
%% @end
%% @since 3.0.0
-spec create_redirect_url(ClientContext, Opts) -> {ok, Uri} | {error, error()} when
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts(),
    Uri :: uri_string:uri_string().
create_redirect_url(#oidcc_client_context{} = ClientContext, Opts) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration} = ClientContext,

    #oidcc_provider_configuration{
        authorization_endpoint = AuthEndpoint, grant_types_supported = GrantTypesSupported
    } =
        ProviderConfiguration,

    maybe
        true ?= lists:member(<<"authorization_code">>, GrantTypesSupported),
        {ok, QueryParams0} ?= redirect_params(ClientContext, Opts),
        QueryParams = QueryParams0 ++ maps:get(url_extension, Opts, []),
        QueryString = uri_string:compose_query(QueryParams),
        {ok, [AuthEndpoint, <<"?">>, QueryString]}
    else
        {error, Reason} ->
            {error, Reason};
        false ->
            {error, {grant_type_not_supported, authorization_code}}
    end.

-spec redirect_params(ClientContext, Opts) -> {ok, oidcc_http_util:query_params()} when
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts().
redirect_params(#oidcc_client_context{client_id = ClientId} = ClientContext, Opts) ->
    QueryParams =
        [
            {<<"response_type">>, maps:get(response_type, Opts, <<"code">>)},
            {<<"client_id">>, ClientId},
            {<<"redirect_uri">>, maps:get(redirect_uri, Opts)}
        ],
    QueryParams1 = maybe_append(<<"state">>, maps:get(state, Opts, undefined), QueryParams),
    QueryParams2 = maybe_append(<<"nonce">>, maps:get(nonce, Opts, undefined), QueryParams1),
    maybe
        {ok, QueryParams3} ?=
            append_code_challenge(
                Opts, QueryParams2, ClientContext
            ),
        QueryParams4 = oidcc_scope:query_append_scope(
            maps:get(scopes, Opts, [openid]), QueryParams3
        ),
        QueryParams5 = maybe_append_dpop_jkt(QueryParams4, ClientContext),
        {ok, QueryParams6} ?= attempt_request_object(QueryParams5, ClientContext),
        attempt_par(QueryParams6, ClientContext, Opts)
    end.

-spec append_code_challenge(Opts, QueryParams, ClientContext) ->
    {ok, oidcc_http_util:query_params()} | {error, error()}
when
    Opts :: opts(),
    QueryParams :: oidcc_http_util:query_params(),
    ClientContext :: oidcc_client_context:t().
append_code_challenge(#{pkce_verifier := CodeVerifier} = Opts, QueryParams, ClientContext) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration} = ClientContext,
    #oidcc_provider_configuration{code_challenge_methods_supported = CodeChallengeMethodsSupported} =
        ProviderConfiguration,
    RequirePkce = maps:get(require_pkce, Opts, false),
    case CodeChallengeMethodsSupported of
        undefined when RequirePkce =:= true ->
            {error, no_supported_code_challenge};
        undefined ->
            {ok, QueryParams};
        Methods when is_list(Methods) ->
            case
                {
                    lists:member(<<"S256">>, CodeChallengeMethodsSupported),
                    lists:member(<<"plain">>, CodeChallengeMethodsSupported)
                }
            of
                {true, _PlainSupported} ->
                    CodeChallenge = base64:encode(crypto:hash(sha256, CodeVerifier), #{
                        mode => urlsafe, padding => false
                    }),
                    {ok, [
                        {<<"code_challenge">>, CodeChallenge},
                        {<<"code_challenge_method">>, <<"S256">>}
                        | QueryParams
                    ]};
                {false, true} ->
                    {ok, [
                        {<<"code_challenge">>, CodeVerifier},
                        {<<"code_challenge_method">>, <<"plain">>}
                        | QueryParams
                    ]};
                {false, false} when RequirePkce =:= true ->
                    {error, no_supported_code_challenge};
                {false, false} ->
                    {ok, QueryParams}
            end
    end;
append_code_challenge(#{require_pkce := true}, _QueryParams, _ClientContext) ->
    {error, pkce_verifier_required};
append_code_challenge(_Opts, QueryParams, _ClientContext) ->
    {ok, QueryParams}.

-spec maybe_append(Key, Value, QueryParams) -> QueryParams when
    Key :: unicode:chardata(),
    Value :: unicode:chardata() | true | undefined,
    QueryParams :: oidcc_http_util:query_params().
maybe_append(_Key, undefined, QueryParams) ->
    QueryParams;
maybe_append(Key, Value, QueryParams) ->
    [{Key, Value} | QueryParams].

-spec maybe_append_dpop_jkt(QueryParams, ClientContext) ->
    QueryParams
when
    ClientContext :: oidcc_client_context:t(),
    QueryParams :: oidcc_http_util:query_params().
maybe_append_dpop_jkt(
    QueryParams,
    #oidcc_client_context{
        client_jwks = #jose_jwk{},
        provider_configuration = #oidcc_provider_configuration{
            dpop_signing_alg_values_supported = [_ | _]
        }
    } = ClientContext
) ->
    #oidcc_client_context{client_jwks = ClientJwks} = ClientContext,
    Thumbprint = jose_jwk:thumbprint(ClientJwks),
    [{"dpop_jkt", Thumbprint} | QueryParams];
maybe_append_dpop_jkt(QueryParams, _ClientContext) ->
    QueryParams.

-spec attempt_request_object(QueryParams, ClientContext) -> {ok, QueryParams} | {error, error()} when
    QueryParams :: oidcc_http_util:query_params(),
    ClientContext :: oidcc_client_context:t().
attempt_request_object(QueryParams, #oidcc_client_context{
    client_id = ClientId,
    client_secret = ClientSecret,
    client_jwks = ClientJwks,
    provider_configuration = #oidcc_provider_configuration{
        issuer = Issuer,
        request_parameter_supported = true,
        require_signed_request_object = RequireSignedRequestObject,
        request_object_signing_alg_values_supported = SigningAlgSupported0,
        request_object_encryption_alg_values_supported = EncryptionAlgSupported0,
        request_object_encryption_enc_values_supported = EncryptionEncSupported0
    },
    jwks = Jwks
}) when ClientSecret =/= unauthenticated ->
    SigningAlgSupported =
        case SigningAlgSupported0 of
            undefined -> [];
            SigningAlgs -> SigningAlgs
        end,
    EncryptionAlgSupported =
        case EncryptionAlgSupported0 of
            undefined -> [];
            EncryptionAlgs -> EncryptionAlgs
        end,
    EncryptionEncSupported =
        case EncryptionEncSupported0 of
            undefined -> [];
            EncryptionEncs -> EncryptionEncs
        end,

    JwksWithClientJwks =
        case ClientJwks of
            none -> Jwks;
            #jose_jwk{} -> oidcc_jwt_util:merge_jwks(Jwks, ClientJwks)
        end,

    SigningJwks =
        case oidcc_jwt_util:client_secret_oct_keys(SigningAlgSupported, ClientSecret) of
            none ->
                JwksWithClientJwks;
            SigningOctJwk ->
                oidcc_jwt_util:merge_jwks(JwksWithClientJwks, SigningOctJwk)
        end,
    EncryptionJwks =
        case oidcc_jwt_util:client_secret_oct_keys(EncryptionAlgSupported, ClientSecret) of
            none ->
                JwksWithClientJwks;
            EncryptionOctJwk ->
                oidcc_jwt_util:merge_jwks(JwksWithClientJwks, EncryptionOctJwk)
        end,

    MaxClockSkew =
        case application:get_env(oidcc, max_clock_skew) of
            undefined -> 0;
            {ok, ClockSkew} -> ClockSkew
        end,

    Claims = maps:merge(
        #{
            <<"iss">> => ClientId,
            <<"aud">> => Issuer,
            <<"jti">> => random_string(32),
            <<"iat">> => os:system_time(seconds),
            <<"exp">> => os:system_time(seconds) + 30,
            <<"nbf">> => os:system_time(seconds) - MaxClockSkew
        },
        maps:from_list(QueryParams)
    ),
    Jwt = jose_jwt:from(Claims),

    case oidcc_jwt_util:sign(Jwt, SigningJwks, deprioritize_none_alg(SigningAlgSupported)) of
        {error, no_supported_alg_or_key} when RequireSignedRequestObject =:= true ->
            {error, request_object_required};
        {error, no_supported_alg_or_key} ->
            {ok, QueryParams};
        {ok, SignedRequestObject} ->
            case
                oidcc_jwt_util:encrypt(
                    SignedRequestObject,
                    EncryptionJwks,
                    deprioritize_none_alg(EncryptionAlgSupported),
                    EncryptionEncSupported
                )
            of
                {ok, EncryptedRequestObject} ->
                    {ok, [{<<"request">>, EncryptedRequestObject} | essential_params(QueryParams)]};
                {error, no_supported_alg_or_key} ->
                    {ok, [{<<"request">>, SignedRequestObject} | essential_params(QueryParams)]}
            end
    end;
attempt_request_object(_QueryParams, #oidcc_client_context{
    provider_configuration = #oidcc_provider_configuration{require_signed_request_object = true}
}) ->
    {error, request_object_required};
attempt_request_object(QueryParams, _ClientContext) ->
    {ok, QueryParams}.

-spec attempt_par(QueryParams, ClientContext, Opts) ->
    {ok, QueryParams} | {error, error()}
when
    QueryParams :: oidcc_http_util:query_params(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts().
attempt_par(
    _QueryParams,
    #oidcc_client_context{
        provider_configuration = #oidcc_provider_configuration{
            require_pushed_authorization_requests = true,
            pushed_authorization_request_endpoint = undefined
        }
    },
    _Opts
) ->
    {error, par_required};
attempt_par(
    QueryParams,
    #oidcc_client_context{
        provider_configuration = #oidcc_provider_configuration{
            pushed_authorization_request_endpoint = undefined
        }
    },
    _Opts
) ->
    {ok, QueryParams};
attempt_par(
    QueryParams,
    #oidcc_client_context{
        client_id = ClientId,
        provider_configuration =
            #oidcc_provider_configuration{
                issuer = Issuer,
                token_endpoint_auth_methods_supported = SupportedAuthMethods,
                token_endpoint_auth_signing_alg_values_supported = SigningAlgs,
                pushed_authorization_request_endpoint = PushedAuthorizationRequestEndpoint
            }
    } = ClientContext,
    Opts
) ->
    Header0 = [{"accept", "application/json"}],

    TelemetryOpts = #{
        topic => [oidcc, par_request], extra_meta => #{issuer => Issuer, client_id => ClientId}
    },

    RequestOpts = maps:get(request_opts, Opts, #{}),
    %% https://datatracker.ietf.org/doc/html/rfc9126#section-2
    %% > To address that ambiguity, the issuer identifier URL of the authorization
    %% > server according to [RFC8414] SHOULD be used as the value of the audience.
    AuthenticationOpts = #{audience => Issuer},

    maybe
        {ok, {Body0, Header}} ?=
            oidcc_auth_util:add_client_authentication(
                QueryParams,
                Header0,
                SupportedAuthMethods,
                SigningAlgs,
                AuthenticationOpts,
                ClientContext
            ),
        %% ensure no duplicate parameters (such as client_id)
        Body = lists:ukeysort(1, Body0),
        Request =
            {PushedAuthorizationRequestEndpoint, Header, "application/x-www-form-urlencoded",
                uri_string:compose_query(Body)},
        {ok, {{json, ParResponse}, _Headers}} ?=
            oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
        #{<<"request_uri">> := ParRequestUri} ?= ParResponse,
        {ok, [{<<"request_uri">>, ParRequestUri}, {<<"client_id">>, ClientId}]}
    else
        {error, Reason} -> {error, Reason};
        #{} = JsonResponse -> {error, {http_error, 201, JsonResponse}}
    end.

-spec essential_params(QueryParams :: oidcc_http_util:query_params()) ->
    oidcc_http_util:query_params().
essential_params(QueryParams) ->
    lists:filter(
        fun
            ({<<"scope">>, _Value}) -> true;
            ({<<"response_type">>, _Value}) -> true;
            ({<<"client_id">>, _Value}) -> true;
            ({<<"redirect_uri">>, _Value}) -> true;
            (_Other) -> false
        end,
        QueryParams
    ).

-spec deprioritize_none_alg(Algorithms :: [binary()]) -> [binary()].
deprioritize_none_alg(Algorithms) ->
    {WithNone, WithoutNone} = lists:partition(
        fun
            (<<"none">>) -> true;
            (_) -> false
        end,
        Algorithms
    ),
    WithoutNone ++ WithNone.

-spec random_string(Bytes :: pos_integer()) -> binary().
random_string(Bytes) ->
    base64:encode(crypto:strong_rand_bytes(Bytes), #{mode => urlsafe, padding => false}).
