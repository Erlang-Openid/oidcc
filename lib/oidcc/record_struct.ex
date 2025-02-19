# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.RecordStruct do
  @moduledoc false

  @callback record_to_struct(record :: tuple()) :: struct()
  @callback struct_to_record(struct :: struct()) :: tuple()

  defmacro __using__(options) do
    internal_name = Keyword.fetch!(options, :internal_name)
    record_name = Keyword.fetch!(options, :record_name)
    record_type_module = Keyword.get(options, :record_type_module, record_name)
    record_type_name = Keyword.get(options, :record_type_name, :t)
    hrl = Keyword.fetch!(options, :hrl)

    quote bind_quoted: [
            internal_name: internal_name,
            record_name: record_name,
            record_type_module: record_type_module,
            record_type_name: record_type_name,
            hrl: hrl,
            behaviour: __MODULE__
          ] do
      @behaviour behaviour

      require Record

      record = Record.extract(record_name, from: hrl)
      keys = :lists.map(&elem(&1, 0), record)
      vals = :lists.map(&{&1, [], nil}, keys)
      pairs = :lists.zip(keys, vals)

      Record.defrecordp(internal_name, record_name, record)

      defstruct record

      @doc false
      @impl behaviour
      @spec record_to_struct(record :: unquote(record_type_module).unquote(record_type_name)()) ::
              t()
      def record_to_struct(record), do: struct!(__MODULE__, unquote(internal_name)(record))

      @doc false
      @impl behaviour
      @spec struct_to_record(struct :: t()) ::
              unquote(record_type_module).unquote(record_type_name)()
      def struct_to_record(%__MODULE__{unquote_splicing(pairs)}),
        do: {unquote(record_name), unquote_splicing(vals)}

      defoverridable record_to_struct: 1, struct_to_record: 1
    end
  end
end
