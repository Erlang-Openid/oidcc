# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Authorization do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :par_request, :start],
    description: "Emitted at the start of executing a PAR request",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :par_request, :stop],
    description: "Emitted at the end of executing a PAR request",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :par_request, :exception],
    description: "Emitted at the end of executing a PAR request",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  @moduledoc """
  Functions to start an OpenID Connect Authorization

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.0.0"

  alias Oidcc.ClientContext

  @doc """
  Create Auth Redirect URL

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.create_redirect_url/4`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://accounts.google.com"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret"
      ...>   )
      ...>
      ...> {:ok, _redirect_uri} =
      ...>   Oidcc.Authorization.create_redirect_url(
      ...>     client_context,
      ...>     %{redirect_uri: "https://my.server/return"}
      ...>   )
  """
  @doc since: "3.0.0"
  @spec create_redirect_url(
          client_context :: ClientContext.t(),
          opts :: :oidcc_authorization.opts()
        ) :: {:ok, :uri_string.uri_string()} | {:error, :oidcc_authorization.error()}
  def create_redirect_url(client_context, opts),
    do:
      client_context
      |> ClientContext.struct_to_record()
      |> :oidcc_authorization.create_redirect_url(opts)
end
