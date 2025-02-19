%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_http_util_SUITE).

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([bad_ssl/1]).
-export([client_cert/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [
        bad_ssl
        %% Disable because of 403
        % client_cert
    ].

init_per_suite(_Config) ->
    {ok, _} = application:ensure_all_started(oidcc),
    [].

end_per_suite(_Config) ->
    ok = application:stop(oidcc).

telemetry_opts() ->
    #{
        topic => [oidcc, oidcc_http_util_SUITE]
    }.

bad_ssl(_Config) ->
    ?assertMatch(
        {error, {failed_connect, _}},
        oidcc_http_util:request(get, {"https://expired.badssl.com/", []}, telemetry_opts(), #{})
    ),

    ?assertMatch(
        {error, {failed_connect, _}},
        oidcc_http_util:request(get, {"https://wrong.host.badssl.com/", []}, telemetry_opts(), #{})
    ),

    ?assertMatch(
        {error, {failed_connect, _}},
        oidcc_http_util:request(get, {"https://self-signed.badssl.com/", []}, telemetry_opts(), #{})
    ),

    ?assertMatch(
        {error, {failed_connect, _}},
        oidcc_http_util:request(
            get, {"https://untrusted-root.badssl.com/", []}, telemetry_opts(), #{}
        )
    ),

    ?assertMatch(
        {error, {failed_connect, _}},
        oidcc_http_util:request(
            get, {"https://tls-v1-1.badssl.com:1011/", []}, telemetry_opts(), #{}
        )
    ),

    ok.

client_cert(_Config) ->
    PrivDir = code:priv_dir(oidcc),
    KeyFile =
        PrivDir ++
            "/test/fixtures/jwk.pem",
    CertFile =
        PrivDir ++
            "/test/fixtures/jwk_cert.pem",
    CertsKeys = [
        #{
            certfile => CertFile,
            keyfile => KeyFile
        }
    ],

    ?assertMatch(
        {error, {http_error, 403, <<"">>}},
        oidcc_http_util:request(
            get, {"https://certauth.idrix.fr/json/", []}, telemetry_opts(), #{
                ssl => [
                    {verify, verify_peer},
                    {cacerts, public_key:cacerts_get()}
                ]
            }
        )
    ),

    inets:start(httpc, [{profile, idrix_fr}]),

    ?assertMatch(
        {ok, {
            {json, #{
                <<"SSL_CLIENT_I_DN">> := <<"CN=Oidcc,O=Erlang Ecosystem Foundation">>
            }},
            _
        }},
        oidcc_http_util:request(
            get, {"https://certauth.idrix.fr/json/", []}, telemetry_opts(), #{
                httpc_profile => idrix_fr,
                ssl => [
                    {verify, verify_peer},
                    {cacerts, public_key:cacerts_get()},
                    {certs_keys, CertsKeys}
                ]
            }
        )
    ),

    ok.
