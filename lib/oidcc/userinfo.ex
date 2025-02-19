# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Userinfo do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :userinfo, :start],
    description: "Emitted at the start of loading userinfo",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :userinfo, :stop],
    description: "Emitted at the end of loading userinfo",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :userinfo, :exception],
    description: "Emitted at the end of loading userinfo",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  @moduledoc """
  OpenID Connect Userinfo

  See https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.0.0"

  alias Oidcc.ClientContext
  alias Oidcc.Token

  @doc """
  Load userinfo for the given token

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.retrieve_userinfo/5`.

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
      ...> # Get access_token from Oidcc.Token.retrieve/3
      ...> access_token = "access_token"
      ...>
      ...> Oidcc.Userinfo.retrieve(
      ...>   access_token,
      ...>   client_context,
      ...>   %{expected_subject: "sub"}
      ...> )
      ...> # => {:ok, %{"sub" => "sub"}}

  """
  @doc since: "3.0.0"
  @spec retrieve(
          access_token :: String.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_userinfo.retrieve_opts()
        ) :: {:ok, :oidcc_jwt_util.claims()} | {:error, :oidcc_userinfo.error()}
  @spec retrieve(
          token :: Token.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_userinfo.retrieve_opts()
        ) :: {:ok, :oidcc_jwt_util.claims()} | {:error, :oidcc_userinfo.error()}
  def retrieve(token, client_context, opts) do
    token =
      case token do
        token when is_binary(token) -> token
        %Token{} = token -> Token.struct_to_record(token)
      end

    client_context = ClientContext.struct_to_record(client_context)

    :oidcc_userinfo.retrieve(token, client_context, opts)
  end
end
