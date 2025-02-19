%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_scope).

-feature(maybe_expr, enable).

-include("internal/doc.hrl").
?MODULEDOC("OpenID Scope Utilities").
?MODULEDOC(#{since => <<"3.0.0">>}).

-export([parse/1]).
-export([query_append_scope/2]).
-export([scopes_to_bin/1]).

-export_type([scopes/0]).
-export_type([t/0]).

?DOC(#{since => <<"3.0.0">>}).
-type scopes() :: [nonempty_binary() | atom() | nonempty_string()].

?DOC(#{since => <<"3.0.0">>}).
-type t() :: binary().

?DOC("""
Compose `t:scopes/0` into `t:t/0`.

## Examples

```erlang
<<"openid profile email">> = oidcc_scope:scopes_to_bin(
  [<<"openid">>, profile, "email"]).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec scopes_to_bin(Scopes :: scopes()) -> t().
scopes_to_bin(Scopes) ->
    NormalizedScopes =
        lists:map(
            fun
                (Scope) when is_binary(Scope) ->
                    Scope;
                (Scope) when is_atom(Scope) ->
                    atom_to_binary(Scope, utf8);
                (Scope) when is_list(Scope) ->
                    list_to_binary(Scope)
            end,
            Scopes
        ),
    SeparatedScopes = lists:join(<<" ">>, NormalizedScopes),
    list_to_binary(SeparatedScopes).

?DOC(false).
-spec query_append_scope(Scope, QueryList) -> QueryList when
    Scope :: t() | scopes(),
    QueryList :: [{unicode:chardata(), unicode:chardata() | true}].
query_append_scope(<<>>, QueryList) ->
    QueryList;
query_append_scope(Scope, QueryList) when is_binary(Scope) ->
    [{<<"scope">>, Scope} | QueryList];
query_append_scope(Scopes, QueryList) when is_list(Scopes) ->
    query_append_scope(scopes_to_bin(Scopes), QueryList).

?DOC("""
Parse `t:t/0` into `t:scopes/0`.

## Examples

```erlang
[<<"openid">>, <<"profile">>] = oidcc_scope:parse(<<"openid profile">>).
```
""").
?DOC(#{since => <<"3.0.0">>}).
-spec parse(Scope :: t()) -> scopes().
parse(Scope) ->
    binary:split(Scope, [<<" ">>], [trim_all, global]).
