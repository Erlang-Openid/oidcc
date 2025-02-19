# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ProviderConfiguration.Worker do
  @moduledoc """
  OIDC Config Provider Worker

  Loads and continuously refreshes the OIDC configuration and JWKs

  ## Usage in Supervisor

  ```elixir
  Supervisor.init([
    {Oidcc.ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
  ], strategy: :one_for_one)
  ```
  """
  @moduledoc since: "3.0.0"

  alias Oidcc.ProviderConfiguration

  @typedoc """
  See `t:oidcc_provider_configuration_worker.opts/0`
  """
  @typedoc since: "3.0.0"
  @type opts() :: %{
          optional(:name) => GenServer.name(),
          required(:issuer) => :uri_string.uri_string(),
          optional(:provider_configuration_opts) => :oidcc_provider_configuration.opts(),
          optional(:backoff_min) => :oidcc_backoff.min(),
          optional(:backoff_max) => :oidcc_backoff.max(),
          optional(:backoff_type) => :oidcc_backoff.type()
        }

  @doc """
  Start Configuration Worker

  ## Examples

      iex> {:ok, _pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com",
      ...>   name: __MODULE__.GoogleConfigProvider
      ...> })
  """
  @doc since: "3.0.0"
  @spec start_link(opts :: opts()) :: GenServer.on_start()
  def start_link(opts)

  def start_link(%{name: name} = opts) when is_atom(name),
    do: :oidcc_provider_configuration_worker.start_link(%{opts | name: {:local, name}})

  def start_link(opts), do: :oidcc_provider_configuration_worker.start_link(opts)

  @spec child_spec(opts :: opts()) :: Supervisor.child_spec()
  def child_spec(opts),
    do:
      Supervisor.child_spec(
        %{
          id: __MODULE__,
          start: {__MODULE__, :start_link, [opts]}
        },
        []
      )

  @doc """
  Get Configuration

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com"
      ...> })
      ...> %Oidcc.ProviderConfiguration{issuer: "https://accounts.google.com"} =
      ...>   Oidcc.ProviderConfiguration.Worker.get_provider_configuration(pid)
  """
  @doc since: "3.0.0"
  @spec get_provider_configuration(name :: GenServer.name()) :: ProviderConfiguration.t()
  def get_provider_configuration(name),
    do:
      name
      |> :oidcc_provider_configuration_worker.get_provider_configuration()
      |> ProviderConfiguration.record_to_struct()

  @doc """
  Get Parsed Jwks

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com"
      ...> })
      ...> %JOSE.JWK{} =
      ...>   Oidcc.ProviderConfiguration.Worker.get_jwks(pid)
  """
  @doc since: "3.0.0"
  @spec get_jwks(name :: GenServer.name()) :: JOSE.JWK.t()
  def get_jwks(name),
    do:
      name
      |> :oidcc_provider_configuration_worker.get_jwks()
      |> JOSE.JWK.from_record()

  @doc """
  Refresh Configuration

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com"
      ...> })
      ...> :ok = Oidcc.ProviderConfiguration.Worker.refresh_configuration(pid)
  """
  @doc since: "3.0.0"
  @spec refresh_configuration(name :: GenServer.name()) :: :ok
  def refresh_configuration(name),
    do: :oidcc_provider_configuration_worker.refresh_configuration(name)

  @doc """
  Refresh JWKs

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com"
      ...> })
      ...> :ok = Oidcc.ProviderConfiguration.Worker.refresh_jwks(pid)
  """
  @doc since: "3.0.0"
  @spec refresh_jwks(name :: GenServer.name()) :: :ok
  def refresh_jwks(name),
    do: :oidcc_provider_configuration_worker.refresh_jwks(name)

  @doc """
  Refresh JWKs if the provided `Kid` is not matching any currently loaded keys

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com"
      ...> })
      ...> :ok = Oidcc.ProviderConfiguration.Worker.refresh_jwks_for_unknown_kid(pid, "kid")
  """
  @doc since: "3.0.0"
  @spec refresh_jwks_for_unknown_kid(name :: GenServer.name(), kid :: String.t()) :: :ok
  def refresh_jwks_for_unknown_kid(name, kid),
    do: :oidcc_provider_configuration_worker.refresh_jwks_for_unknown_kid(name, kid)
end
