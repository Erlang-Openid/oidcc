%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_http_util).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("HTTP Client Utilities").

-export([basic_auth_header/2]).
-export([bearer_auth_header/1]).
-export([headers_to_cache_deadline/2]).
-export([request/4]).

-export_type([
    http_header/0, error/0, httpc_error/0, query_params/0, telemetry_opts/0, request_opts/0
]).

?DOC("See `uri_string:compose_query/1`.").
?DOC(#{since => <<"3.0.0">>}).
-type query_params() :: [{unicode:chardata(), unicode:chardata() | true}].

?DOC("See `httpc:request/5`.").
?DOC(#{since => <<"3.0.0">>}).
-type http_header() :: {Field :: [byte()] | binary(), Value :: iodata()}.

?DOC(#{since => <<"3.0.0">>}).
-type error() ::
    {http_error, StatusCode :: pos_integer(), HttpBodyResult :: binary() | map()}
    | {use_dpop_nonce, Nonce :: binary(), HttpBodyResult :: binary() | map()}
    | invalid_content_type
    | httpc_error().

?DOC("See `httpc:request/5` for additional errors.").
?DOC(#{since => <<"3.0.0">>}).
-type httpc_error() :: term().

?DOC("""
See `httpc:request/5`.

## Parameters

* `timeout` - timeout for request
* `ssl` - TLS config
""").
?DOC(#{since => <<"3.0.0">>}).
-type request_opts() :: #{
    timeout => timeout(),
    ssl => [ssl:tls_option()],
    httpc_profile => atom() | pid()
}.

?DOC(#{since => <<"3.0.0">>}).
-type telemetry_opts() :: #{
    topic := [atom()],
    extra_meta => map()
}.

?DOC(false).
-spec basic_auth_header(User, Secret) -> http_header() when
    User :: binary(),
    Secret :: binary().
basic_auth_header(User, Secret) ->
    UserEnc = uri_string:compose_query([{User, true}]),
    SecretEnc = uri_string:compose_query([{Secret, true}]),
    RawAuth = <<UserEnc/binary, <<":">>/binary, SecretEnc/binary>>,
    AuthData = base64:encode(RawAuth),
    {"authorization", [<<"Basic ">>, AuthData]}.

?DOC(false).
-spec bearer_auth_header(Token) -> http_header() when Token :: binary().
bearer_auth_header(Token) ->
    {"authorization", [<<"Bearer ">>, Token]}.

?DOC(false).
-spec request(Method, Request, TelemetryOpts, RequestOpts) ->
    {ok, {{json, term()} | {jwt, binary()}, [http_header()]}}
    | {error, error()}
when
    Method :: head | get | put | patch | post | trace | options | delete,
    Request ::
        {uri_string:uri_string(), [http_header()]}
        | {
            uri_string:uri_string(),
            [http_header()],
            ContentType :: uri_string:uri_string(),
            HttpBody
        },
    HttpBody ::
        iolist()
        | binary()
        | {
            fun((Accumulator :: term()) -> eof | {ok, iolist(), Accumulator :: term()}),
            Accumulator :: term()
        }
        | {chunkify, fun((Accumulator :: term()) -> eof | {ok, iolist(), Accumulator :: term()}),
            Accumulator :: term()},
    TelemetryOpts :: telemetry_opts(),
    RequestOpts :: request_opts().
request(Method, Request, TelemetryOpts, RequestOpts) ->
    TelemetryTopic = maps:get(topic, TelemetryOpts),
    TelemetryExtraMeta = maps:get(extra_meta, TelemetryOpts, #{}),
    Timeout = maps:get(timeout, RequestOpts, timer:minutes(1)),
    SslOpts = maps:get(ssl, RequestOpts, undefined),
    HttpProfile = maps:get(httpc_profile, RequestOpts, default),

    HttpOpts0 = [{timeout, Timeout}],
    HttpOpts =
        case SslOpts of
            undefined -> HttpOpts0;
            _Opts -> [{ssl, SslOpts} | HttpOpts0]
        end,

    telemetry:span(
        TelemetryTopic,
        TelemetryExtraMeta,
        fun() ->
            maybe
                {ok, {_StatusLine, Headers, _Result} = Response} ?=
                    httpc:request(
                        Method,
                        Request,
                        HttpOpts,
                        [{body_format, binary}],
                        HttpProfile
                    ),
                {ok, BodyAndFormat} ?= extract_successful_response(Response),
                {{ok, {BodyAndFormat, Headers}}, TelemetryExtraMeta}
            else
                {error, Reason} ->
                    {{error, Reason}, maps:put(error, Reason, TelemetryExtraMeta)}
            end
        end
    ).

-spec extract_successful_response({StatusLine, [HttpHeader], HttpBodyResult}) ->
    {ok, {json, term()} | {jwt, binary()}} | {error, error()}
when
    StatusLine :: {HttpVersion, StatusCode, string()},
    HttpVersion :: uri_string:uri_string(),
    StatusCode :: pos_integer(),
    HttpHeader :: http_header(),
    HttpBodyResult :: binary().
extract_successful_response({{_HttpVersion, Status, _HttpStatusName}, Headers, HttpBodyResult}) when
    Status == 200 orelse Status == 201
->
    case fetch_content_type(Headers) of
        json ->
            {ok, {json, jose:decode(HttpBodyResult)}};
        jwt ->
            {ok, {jwt, HttpBodyResult}};
        unknown ->
            {error, invalid_content_type}
    end;
extract_successful_response({{_HttpVersion, StatusCode, _HttpStatusName}, Headers, HttpBodyResult}) ->
    Body =
        case fetch_content_type(Headers) of
            json ->
                jose:decode(HttpBodyResult);
            jwt ->
                HttpBodyResult;
            unknown ->
                HttpBodyResult
        end,
    case proplists:lookup("dpop-nonce", Headers) of
        {"dpop-nonce", DpopNonce} ->
            {error, {use_dpop_nonce, iolist_to_binary(DpopNonce), Body}};
        _ ->
            {error, {http_error, StatusCode, Body}}
    end.

-spec fetch_content_type(Headers) -> json | jwt | unknown when Headers :: [http_header()].
fetch_content_type(Headers) ->
    case proplists:lookup("content-type", Headers) of
        {"content-type", "application/jwk-set+json" ++ _Rest} ->
            json;
        {"content-type", "application/json" ++ _Rest} ->
            json;
        {"content-type", "application/jwt" ++ _Rest} ->
            jwt;
        _Other ->
            unknown
    end.

-spec headers_to_cache_deadline(Headers, DefaultExpiry) -> pos_integer() when
    Headers :: [{Header :: binary(), Value :: binary()}], DefaultExpiry :: non_neg_integer().
headers_to_cache_deadline(Headers, DefaultExpiry) ->
    case proplists:lookup("cache-control", Headers) of
        {"cache-control", Cache} ->
            try
                cache_deadline(Cache, DefaultExpiry)
            catch
                _:_ ->
                    DefaultExpiry
            end;
        none ->
            DefaultExpiry
    end.

-spec cache_deadline(Cache :: iodata(), Fallback :: pos_integer()) -> pos_integer().
cache_deadline(Cache, Fallback) ->
    Entries =
        binary:split(iolist_to_binary(Cache), [<<",">>, <<"=">>, <<" ">>], [global, trim_all]),
    MaxAge =
        fun
            (<<"0">>, true) ->
                Fallback;
            (Entry, true) ->
                erlang:convert_time_unit(binary_to_integer(Entry), second, millisecond);
            (<<"max-age">>, _) ->
                true;
            (_, Res) ->
                Res
        end,
    lists:foldl(MaxAge, Fallback, Entries).
