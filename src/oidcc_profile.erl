%%%-------------------------------------------------------------------
%% @doc OpenID Profile Utilities
%% @end
%% @since 3.2.0
%%%-------------------------------------------------------------------
-module(oidcc_profile).

-feature(maybe_expr, enable).

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").

-export([apply_profiles/2]).

-export_type([profile/0]).
-export_type([opts/0]).
-export_type([opts_no_profiles/0]).
-export_type([error/0]).

-type profile() :: fapi2_security_profile | fapi2_message_signing.
-type opts() :: #{
    profiles => [profile()],
    require_pkce => boolean(),
    trusted_audiences => [binary()] | any,
    preferred_auth_methods => [oidcc_auth_util:auth_method()],
    request_opts => oidcc_http_util:request_opts()
}.
-type opts_no_profiles() :: #{
    require_pkce => boolean(),
    trusted_audiences => [binary()] | any,
    preferred_auth_methods => [oidcc_auth_util:auth_method()],
    request_opts => oidcc_http_util:request_opts()
}.
-type error() :: {unknown_profile, atom()}.

%% @private
-spec apply_profiles(ClientContext, opts()) ->
    {ok, ClientContext, opts_no_profiles()} | {error, error()}
when
    ClientContext :: oidcc_client_context:t().
apply_profiles(
    #oidcc_client_context{} = ClientContext0,
    #{profiles := [fapi2_security_profile | RestProfiles]} = Opts0
) ->
    %% FAPI2 Security Profile
    %% - https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html
    {ClientContext1, Opts1} = enforce_s256_pkce(ClientContext0, Opts0),
    ClientContext2 = limit_response_types([<<"code">>], ClientContext1),
    ClientContext3 = enforce_par(ClientContext2),
    ClientContext4 = enforce_iss_parameter(ClientContext3),
    ClientContext = limit_signing_alg_values(
        [
            <<"PS256">>,
            <<"PS384">>,
            <<"PS512">>,
            <<"ES256">>,
            <<"ES384">>,
            <<"ES512">>,
            <<"EdDSA">>
        ],
        ClientContext4
    ),
    Opts2 = Opts1#{profiles => RestProfiles},
    Opts3 = map_put_new(trusted_audiences, [], Opts2),
    Opts4 = map_put_new(preferred_auth_methods, [private_key_jwt, tls_client_auth], Opts3),
    Opts5 = put_tls_defaults(Opts4),
    Opts = limit_tls_ciphers(
        [
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        ],
        Opts5
    ),
    apply_profiles(ClientContext, Opts);
apply_profiles(
    #oidcc_client_context{} = ClientContext0,
    #{profiles := [fapi2_message_signing | RestProfiles]} = Opts0
) ->
    %% FAPI2 Message Signing:
    %% - https://openid.bitbucket.io/fapi/fapi-2_0-message-signing.html

    ClientContext = limit_response_modes(
        [<<"jwt">>, <<"query.jwt">>, <<"form_post.jwt">>], ClientContext0
    ),

    %% TODO force require_signed_request_object once the conformance suite can
    %% validate it (currently, the suite fails if this is enabled)
    %% TODO require signed token introspection responses

    %% Also require everything from FAPI2 Security Profile
    Opts = Opts0#{profiles => [fapi2_security_profile | RestProfiles]},
    apply_profiles(ClientContext, Opts);
apply_profiles(#oidcc_client_context{}, #{profiles := [UnknownProfile | _]}) ->
    {error, {unknown_profile, UnknownProfile}};
apply_profiles(#oidcc_client_context{} = ClientContext, #{profiles := []} = Opts0) ->
    Opts = maps:remove(profiles, Opts0),
    apply_profiles(ClientContext, Opts);
apply_profiles(#oidcc_client_context{} = ClientContext, #{} = Opts) ->
    {ok, ClientContext, Opts}.

enforce_s256_pkce(ClientContext0, Opts0) ->
    #oidcc_client_context{
        provider_configuration =
            ProviderConfiguration0 = #oidcc_provider_configuration{
                code_challenge_methods_supported = CodeChallengeMethodsSupported
            }
    } = ClientContext0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        code_challenge_methods_supported = limit_values([<<"S256">>], CodeChallengeMethodsSupported)
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    Opts = Opts0#{require_pkce => true},
    {ClientContext, Opts}.

limit_response_types(Types, ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    #oidcc_provider_configuration{
        response_types_supported = ResponseTypes
    } = ProviderConfiguration0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        response_types_supported = limit_values(Types, ResponseTypes)
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

limit_response_modes(Modes, ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    #oidcc_provider_configuration{
        response_modes_supported = ResponseModes
    } = ProviderConfiguration0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        response_modes_supported = limit_values(Modes, ResponseModes)
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

enforce_par(ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        require_pushed_authorization_requests = true
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

enforce_iss_parameter(ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        authorization_response_iss_parameter_supported = true
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

limit_signing_alg_values(AlgSupported, ClientContext0) ->
    #oidcc_client_context{provider_configuration = ProviderConfiguration0} = ClientContext0,
    #oidcc_provider_configuration{
        id_token_signing_alg_values_supported = IdAlg,
        userinfo_signing_alg_values_supported = UserinfoAlg,
        request_object_signing_alg_values_supported = RequestObjectAlg,
        token_endpoint_auth_signing_alg_values_supported = TokenAlg,
        revocation_endpoint_auth_signing_alg_values_supported = RevocationAlg,
        introspection_endpoint_auth_signing_alg_values_supported = IntrospectionAlg,
        authorization_signing_alg_values_supported = AuthorizationAlg,
        dpop_signing_alg_values_supported = DpopAlg
    } = ProviderConfiguration0,
    ProviderConfiguration = ProviderConfiguration0#oidcc_provider_configuration{
        id_token_signing_alg_values_supported = limit_values(AlgSupported, IdAlg),
        userinfo_signing_alg_values_supported = limit_values(AlgSupported, UserinfoAlg),
        request_object_signing_alg_values_supported = limit_values(AlgSupported, RequestObjectAlg),
        token_endpoint_auth_signing_alg_values_supported = limit_values(AlgSupported, TokenAlg),
        revocation_endpoint_auth_signing_alg_values_supported = limit_values(
            AlgSupported, RevocationAlg
        ),
        introspection_endpoint_auth_signing_alg_values_supported = limit_values(
            AlgSupported, IntrospectionAlg
        ),
        authorization_signing_alg_values_supported = limit_values(AlgSupported, AuthorizationAlg),
        dpop_signing_alg_values_supported = limit_values(AlgSupported, DpopAlg)
    },
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = ProviderConfiguration
    },
    ClientContext.

put_tls_defaults(Opts) ->
    RequestOpts0 = maps:get(request_opts, Opts, #{}),
    SslOpts0 = maps:get(ssl, RequestOpts0, []),
    SslOpts1 = SslOpts0 ++ httpc:ssl_verify_host_options(true),
    SslOpts = lists:ukeysort(1, SslOpts1),
    RequestOpts = RequestOpts0#{ssl => SslOpts},
    Opts#{request_opts => RequestOpts}.

limit_tls_ciphers(SupportedCipherStrs, Opts) ->
    RequestOpts0 = maps:get(request_opts, Opts, #{}),
    SslOpts0 = maps:get(ssl, RequestOpts0, []),
    SupportedCiphers = lists:map(fun ssl:str_to_suite/1, SupportedCipherStrs),
    SslOpts1 = [{ciphers, SupportedCiphers} | SslOpts0],
    SslOpts = lists:ukeysort(1, SslOpts1),
    RequestOpts = RequestOpts0#{ssl => SslOpts},
    Opts#{request_opts => RequestOpts}.

limit_values(_Limit, undefined) ->
    undefined;
limit_values(Limit, Values) ->
    [V || V <- Values, lists:member(V, Limit)].

map_put_new(Key, Value, Map) ->
    case Map of
        #{Key := _} ->
            Map;
        _ ->
            Map#{Key => Value}
    end.
