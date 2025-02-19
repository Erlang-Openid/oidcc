# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Token.Access do
  @moduledoc """
  Access Token struct.

  See `t::oidcc_token.access/0`
  """
  @moduledoc since: "3.0.0"

  alias Oidcc.ClientContext

  use Oidcc.RecordStruct,
    internal_name: :token,
    record_name: :oidcc_token_access,
    record_type_module: :oidcc_token,
    record_type_name: :access,
    hrl: "include/oidcc_token.hrl"

  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          token: String.t(),
          expires: pos_integer() | :undefined,
          type: String.t()
        }

  @doc """
  Generate a map of authorization headers to use when using the given
  `Oidcc.Token.Access` struct to access an API endpoint.
  """
  @doc since: "3.2.0"
  @spec authorization_headers(
          access_token :: t(),
          method :: :get | :post,
          endpoint :: String.t(),
          client_context :: ClientContext.t()
        ) :: %{String.t() => String.t()}
  @spec authorization_headers(
          access_token :: t(),
          method :: :get | :post,
          endpoint :: String.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token.authorization_headers_opts()
        ) :: %{String.t() => String.t()}
  def authorization_headers(
        access_token,
        method,
        endpoint,
        client_context,
        opts \\ %{}
      ),
      do:
        :oidcc_token.authorization_headers(
          struct_to_record(access_token),
          method,
          endpoint,
          ClientContext.struct_to_record(client_context),
          opts
        )
end
