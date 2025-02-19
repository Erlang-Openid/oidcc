# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ClientRegistration.Response do
  @moduledoc """
  Client Registration Response Struct
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :response,
    record_name: :oidcc_client_registration_response,
    record_type_module: :oidcc_client_registration,
    record_type_name: :response,
    hrl: "include/oidcc_client_registration.hrl"

  @typedoc """
  Client Registration Response Struct

  See https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
  """
  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          client_id: String.t(),
          client_secret: String.t() | :undefined,
          registration_access_token: String.t() | :undefined,
          registration_client_uri: :uri_string.uri_string() | :undefined,
          client_id_issued_at: pos_integer() | :undefined,
          client_secret_expires_at: pos_integer() | :undefined,
          extra_fields: %{String.t() => term()}
        }
end
