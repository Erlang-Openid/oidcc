%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-FileCopyrightText: 2016-2024 Ecto DB Connection Contributors
%% SPDX-License-Identifier: Apache-2.0

%% Based on https://github.com/elixir-ecto/db_connection/blob/8ef1f2ea54922873590b8939f2dad6b031c5b49c/test/db_connection/backoff_test.exs

-module(oidcc_backoff_test).

-include_lib("eunit/include/eunit.hrl").

exp_backoff_in_min_max_test() ->
    Min = 1000,
    Max = 30000,
    lists:map(
        fun(Retry) ->
            ?assertMatch({wait, _}, Retry),

            {wait, Wait} = Retry,

            ?assert(Wait >= Min),
            ?assert(Wait =< Max)
        end,
        calculate_backoffs(20, exponential, Min, Max)
    ).

exp_backoff_double_until_max_test() ->
    Min = 1000,
    Max = 30000,
    lists:foldl(
        fun
            ({wait, Wait}, undefined) ->
                Wait;
            (Retry, Prev) ->
                ?assertMatch({wait, _}, Retry),

                {wait, Wait} = Retry,

                ?assert(((Wait div 2) =:= Prev) or (Wait =:= Max)),

                Wait
        end,
        undefined,
        calculate_backoffs(20, exponential, Min, Max)
    ).

rand_backoff_in_min_max_test() ->
    Min = 1000,
    Max = 30000,
    lists:map(
        fun(Retry) ->
            ?assertMatch({wait, _}, Retry),

            {wait, Wait} = Retry,

            ?assert(Wait >= Min),
            ?assert(Wait =< Max)
        end,
        calculate_backoffs(20, random, Min, Max)
    ).

rand_backoff_different_every_time_test() ->
    Min = 1000,
    Max = 30000,
    Comparison = calculate_backoffs(20, random, Min, Max),
    lists:map(
        fun(_) ->
            ?assertNotEqual(Comparison, calculate_backoffs(20, random, Min, Max))
        end,
        lists:seq(1, 100)
    ).

rand_exp_backoff_in_min_max_test() ->
    Min = 1000,
    Max = 30000,
    lists:map(
        fun(Retry) ->
            ?assertMatch({wait, _}, Retry),

            {wait, Wait} = Retry,

            ?assert(Wait >= Min),
            ?assert(Wait =< Max)
        end,
        calculate_backoffs(20, random_exponential, Min, Max)
    ).

rand_exp_backoff_increase_until_third_max_test() ->
    Min = 1000,
    Max = 30000,
    lists:foldl(
        fun
            ({wait, Wait}, undefined) ->
                Wait;
            (Retry, Prev) ->
                ?assertMatch({wait, _}, Retry),

                {wait, Wait} = Retry,

                ?assert((Wait >= Prev) or (Wait >= (Max div 3))),

                Wait
        end,
        undefined,
        calculate_backoffs(20, random_exponential, Min, Max)
    ).

calculate_backoffs(N, Type, Min, Max) ->
    lists:reverse(calculate_backoffs(N, Type, Min, Max, undefined, [])).

calculate_backoffs(0, _Type, _Min, _Max, _State, Acc) ->
    Acc;
calculate_backoffs(N, Type, Min, Max, State, Acc) ->
    case oidcc_backoff:handle_retry(Type, Min, Max, State) of
        stop ->
            [stop | Acc];
        {Wait, NewState} ->
            calculate_backoffs(N - 1, Type, Min, Max, NewState, [{wait, Wait} | Acc])
    end.
