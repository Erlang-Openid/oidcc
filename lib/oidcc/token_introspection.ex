# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.TokenIntrospection do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :introspect_token, :start],
    description: "Emitted at the start of introspecting the token",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :introspect_token, :stop],
    description: "Emitted at the end of introspecting the token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :introspect_token, :exception],
    description: "Emitted at the end of introspecting the token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  @moduledoc """
  OAuth Token Introspection

  See https://datatracker.ietf.org/doc/html/rfc7662

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :introspection,
    record_name: :oidcc_token_introspection,
    hrl: "include/oidcc_token_introspection.hrl"

  alias Oidcc.ClientContext
  alias Oidcc.Token

  @typedoc """
  For details on the fields see:
  * https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
  """
  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          active: boolean(),
          client_id: binary(),
          exp: pos_integer() | :undefined,
          scope: :oidcc_scope.scopes(),
          username: binary() | :undefined,
          token_type: binary() | :undefined,
          iat: pos_integer() | :undefined,
          nbf: pos_integer() | :undefined,
          sub: binary() | :undefined,
          aud: binary() | :undefined,
          iss: binary() | :undefined,
          jti: binary() | :undefined,
          extra: %{binary() => term()}
        }

  @doc """
  Introspect the given access token

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.introspect_token/5`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://api.login.yahoo.com"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret"
      ...>   )
      ...>
      ...> Oidcc.TokenIntrospection.introspect(
      ...>   "access_token",
      ...>   client_context
      ...> )
      ...> # => {:ok, %Oidcc.TokenIntrospection{}}
  """
  @doc since: "3.0.0"
  @spec introspect(
          token :: String.t() | Token.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token_introspection.opts()
        ) :: {:ok, t()} | {:error, :oidcc_token_introspection.error()}
  def introspect(token, client_context, opts \\ %{}) do
    client_context = ClientContext.struct_to_record(client_context)

    token =
      case token do
        token when is_binary(token) -> token
        %Token{} = token -> Token.struct_to_record(token)
      end

    with {:ok, introspection} <-
           :oidcc_token_introspection.introspect(token, client_context, opts) do
      {:ok, record_to_struct(introspection)}
    end
  end
end
