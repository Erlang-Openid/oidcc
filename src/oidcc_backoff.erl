%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_backoff).

-include("internal/doc.hrl").
?MODULEDOC("""
Backoff Handling

Based on [`db_connection`](https://github.com/elixir-ecto/db_connection/blob/8ef1f2ea54922873590b8939f2dad6b031c5b49c/lib/db_connection/backoff.ex#L24)
""").
?MODULEDOC(#{since => <<"3.2.0">>}).

-export_type([type/0]).
-export_type([min/0]).
-export_type([max/0]).
-export_type([state/0]).

-export([handle_retry/4]).

?DOC(#{since => <<"3.2.0">>}).
-type type() :: stop | exponential | random | random_exponential.

?DOC(#{since => <<"3.2.0">>}).
-type min() :: pos_integer().

?DOC(#{since => <<"3.2.0">>}).
-type max() :: pos_integer().

?DOC(#{since => <<"3.2.0">>}).
-opaque state() :: pos_integer() | {pos_integer(), pos_integer()}.

?DOC(false).
-spec handle_retry(Type, Min, Max, State) -> stop | {Wait, State} when
    Type :: type(), Min :: min(), Max :: max(), State :: undefined | state(), Wait :: pos_integer().
handle_retry(Type, Min, Max, State) when Min > 0, Max > 0, Max >= Min ->
    priv_handle_retry(Type, Min, Max, State).

-spec priv_handle_retry(Type, Min, Max, State) -> stop | {Wait, State} when
    Type :: type(), Min :: min(), Max :: max(), State :: undefined | state(), Wait :: pos_integer().
priv_handle_retry(stop, _Min, _Max, undefined) ->
    stop;
priv_handle_retry(random, Min, Max, State) ->
    {rand(Min, Max), State};
priv_handle_retry(exponential, Min, _Max, undefined) ->
    {Min, Min};
priv_handle_retry(exponential, _Min, Max, State) ->
    Wait = min(State * 2, Max),
    {Wait, Wait};
priv_handle_retry(random_exponential, Min, Max, undefined) ->
    Lower = max(Min, Max div 3),
    priv_handle_retry(random_exponential, Min, Max, {Lower, Lower});
priv_handle_retry(random_exponential, _Min, Max, {Prev, Lower}) ->
    NextMin = min(Prev, Lower),
    NextMax = min(Prev * 3, Max),
    Next = rand(NextMin, NextMax),
    priv_handle_retry(random, NextMin, NextMax, {Next, Lower}).

rand(Min, Max) -> rand:uniform(Max - Min + 1) + Min - 1.
