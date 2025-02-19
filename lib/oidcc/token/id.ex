# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Token.Id do
  @moduledoc """
  ID Token struct
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :token,
    record_name: :oidcc_token_id,
    record_type_module: :oidcc_token,
    record_type_name: :id,
    hrl: "include/oidcc_token.hrl"

  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          token: String.t(),
          claims: :oidcc_jwt_util.claims()
        }
end
