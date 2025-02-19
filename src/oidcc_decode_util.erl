%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_decode_util).

-include("internal/doc.hrl").
?MODULEDOC("Response Decoding Utils").
?MODULEDOC(#{since => <<"3.0.0">>}).

-export([extract/3]).
-export([parse_setting_binary/2]).
-export([parse_setting_binary_list/2]).
-export([parse_setting_boolean/2]).
-export([parse_setting_list_enum/3]).
-export([parse_setting_number/2]).
-export([parse_setting_uri/2]).
-export([parse_setting_uri_https/2]).
-export([parse_setting_uri_map/2]).
-export([parse_setting_uri_https_map/2]).

-export_type([error/0]).

?DOC(#{since => <<"3.0.0">>}).
-type error() ::
    {missing_config_property, Key :: atom()}
    | {invalid_config_property, {
        Type ::
            uri
            | uri_https
            | binary
            | number
            | list_of_binaries
            | boolean
            | scopes_including_openid
            | enum
            | alg_no_none,
        Field :: atom()
    }}.

?DOC(false).
-spec extract(
    Map :: #{binary() => term()},
    Keys :: [{required, Key, ParseFn} | {optional, Key, Default, ParseFn}],
    Acc :: #{atom() => term()}
) ->
    {ok, {Matched, Rest}} | {error, error()}
when
    Key :: atom(),
    Default :: term(),
    ParseFn :: fun((Setting :: term(), Key) -> {ok, term()} | {error, error()}),
    Matched :: #{Key => Default | undefined | term()},
    Rest :: #{binary() => term()}.
extract(Map1, [{required, Key, ParseFn} | RestKeys], Acc) ->
    case maps:take(atom_to_binary(Key), Map1) of
        {Value, Map2} ->
            case ParseFn(Value, Key) of
                {ok, Parsed} ->
                    extract(Map2, RestKeys, maps:put(Key, Parsed, Acc));
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, {missing_config_property, Key}}
    end;
extract(Map1, [{optional, Key, Default, ParseFn} | RestKeys], Acc) ->
    case maps:take(atom_to_binary(Key), Map1) of
        {Value, Map2} ->
            case ParseFn(Value, Key) of
                {ok, Parsed} ->
                    extract(Map2, RestKeys, maps:put(Key, Parsed, Acc));
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            extract(Map1, RestKeys, maps:put(Key, Default, Acc))
    end;
extract(Map, [], Acc) ->
    {ok, {Acc, Map}}.

?DOC(false).
-spec parse_setting_uri(Setting :: term(), Field :: atom()) ->
    {ok, uri_string:uri_string()} | {error, error()}.
parse_setting_uri(Setting, _Field) when is_binary(Setting) ->
    {ok, Setting};
parse_setting_uri(_Setting, Field) ->
    {error, {invalid_config_property, {uri, Field}}}.

?DOC(false).
-spec parse_setting_uri_https(Setting :: term(), Field :: atom()) ->
    {ok, uri_string:uri_string()} | {error, error()}.
parse_setting_uri_https(Setting, Field) when is_binary(Setting) ->
    case uri_string:parse(Setting) of
        #{scheme := <<"https">>} ->
            {ok, Setting};
        #{scheme := _Scheme} ->
            {error, {invalid_config_property, {uri_https, Field}}}
    end;
parse_setting_uri_https(_Setting, Field) ->
    {error, {invalid_config_property, {uri_https, Field}}}.

?DOC(false).
-spec parse_setting_uri_map(Setting :: term(), Field :: atom()) ->
    {ok, #{binary() => uri_string:uri_string()}} | {error, error()}.
parse_setting_uri_map(Setting, Field) ->
    do_parse_setting_uri_map(Setting, Field, fun parse_setting_uri/2).

?DOC(false).
-spec parse_setting_uri_https_map(Setting :: term(), Field :: atom()) ->
    {ok, #{binary() => uri_string:uri_string()}} | {error, error()}.
parse_setting_uri_https_map(Setting, Field) ->
    do_parse_setting_uri_map(Setting, Field, fun parse_setting_uri_https/2).

do_parse_setting_uri_map(#{} = Setting, Field, Parser) ->
    SettingList = maps:to_list(Setting),
    case
        lists:foldl(
            fun
                (_Elem, {error, Reason}) ->
                    {error, Reason};
                ({BinKey, Value}, {ok, Acc}) when is_binary(BinKey) ->
                    case Parser(Value, Field) of
                        {ok, SettingValue} ->
                            {ok, [{BinKey, SettingValue} | Acc]};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                (_, _) ->
                    {error, {invalid_config_property, {uri_map, Field}}}
            end,

            {ok, []},
            SettingList
        )
    of
        {ok, ParsedList} ->
            {ok, maps:from_list(ParsedList)};
        {error, Reason} ->
            {error, Reason}
    end;
do_parse_setting_uri_map(_Setting, Field, _Parser) ->
    {error, {invalid_config_property, {uri_map, Field}}}.

?DOC(false).
-spec parse_setting_binary(Setting :: term(), Field :: atom()) ->
    {ok, binary()} | {error, error()}.
parse_setting_binary(Setting, _Field) when is_binary(Setting) ->
    {ok, Setting};
parse_setting_binary(_Setting, Field) ->
    {error, {invalid_config_property, {binary, Field}}}.

?DOC(false).
-spec parse_setting_binary_list(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_setting_binary_list(Setting, Field) when is_list(Setting) ->
    case lists:all(fun is_binary/1, Setting) of
        true ->
            {ok, Setting};
        false ->
            {error, {invalid_config_property, {list_of_binaries, Field}}}
    end;
parse_setting_binary_list(_Setting, Field) ->
    {error, {invalid_config_property, {list_of_binaries, Field}}}.

?DOC(false).
-spec parse_setting_number(Setting :: term(), Field :: atom()) ->
    {ok, integer()} | {error, error()}.
parse_setting_number(Setting, _Field) when is_integer(Setting) ->
    {ok, Setting};
parse_setting_number(_Setting, Field) ->
    {error, {invalid_config_property, {number, Field}}}.

?DOC(false).
-spec parse_setting_boolean(Setting :: term(), Field :: atom()) ->
    {ok, boolean()} | {error, error()}.
parse_setting_boolean(Setting, _Field) when is_boolean(Setting) ->
    {ok, Setting};
parse_setting_boolean(_Setting, Field) ->
    {error, {invalid_config_property, {boolean, Field}}}.

?DOC(false).
-spec parse_setting_list_enum(
    Setting :: term(),
    Field :: atom(),
    Parse :: fun((binary()) -> {ok, Value} | error)
) ->
    {ok, [Value]} | {error, error()}
when
    Value :: term().
parse_setting_list_enum(Setting, Field, Parse) ->
    case parse_setting_binary_list(Setting, Field) of
        {ok, Values} ->
            Parsed =
                lists:map(
                    fun(Value) ->
                        case Parse(Value) of
                            {ok, ParsedValue} ->
                                {ok, ParsedValue};
                            error ->
                                {error, Value}
                        end
                    end,
                    Values
                ),

            case
                lists:filter(
                    fun
                        ({ok, _Value}) ->
                            false;
                        ({error, _Value}) ->
                            true
                    end,
                    Parsed
                )
            of
                [] ->
                    {ok, lists:map(fun({ok, Value}) -> Value end, Parsed)};
                [{error, _InvalidValue} | _Rest] ->
                    {error, {invalid_config_property, {enum, Field}}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.
