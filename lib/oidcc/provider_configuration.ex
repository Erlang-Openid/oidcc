# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ProviderConfiguration do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :load_configuration, :start],
    description: "Emitted at the start of loading the provider configuration",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string()}"
  })

  telemetry_event(%{
    event: [:oidcc, :load_configuration, :stop],
    description: "Emitted at the end of loading the provider configuration",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string()}"
  })

  telemetry_event(%{
    event: [:oidcc, :load_configuration, :exception],
    description: "Emitted at the end of loading the provider configuration",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string()}"
  })

  telemetry_event(%{
    event: [:oidcc, :load_jwks, :start],
    description: "Emitted at the start of loading the provider jwks",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{jwks_uri: :uri_string.uri_string()}"
  })

  telemetry_event(%{
    event: [:oidcc, :load_jwks, :stop],
    description: "Emitted at the end of loading the provider jwks",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{jwks_uri: :uri_string.uri_string()}"
  })

  telemetry_event(%{
    event: [:oidcc, :load_jwks, :exception],
    description: "Emitted at the end of loading the provider jwks",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{jwks_uri: :uri_string.uri_string()}"
  })

  @moduledoc """
  Tooling to load and parse Openid Configuration

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :configuration,
    record_name: :oidcc_provider_configuration,
    hrl: "include/oidcc_provider_configuration.hrl"

  @typedoc """
  Configuration Struct

  For details on the fields see:
  * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  * https://datatracker.ietf.org/doc/html/draft-jones-oauth-discovery-01#section-4.1
  * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
  """
  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          issuer: :uri_string.uri_string(),
          authorization_endpoint: :uri_string.uri_string(),
          token_endpoint: :uri_string.uri_string() | :undefined,
          userinfo_endpoint: :uri_string.uri_string() | :undefined,
          jwks_uri: :uri_string.uri_string() | :undefined,
          registration_endpoint: :uri_string.uri_string() | :undefined,
          scopes_supported: [String.t()] | :undefined,
          response_types_supported: [String.t()],
          response_modes_supported: [String.t()],
          grant_types_supported: [String.t()],
          acr_values_supported: [String.t()] | :undefined,
          subject_types_supported: [:pairwise | :public],
          id_token_signing_alg_values_supported: [String.t()],
          id_token_encryption_alg_values_supported: [String.t()] | :undefined,
          id_token_encryption_enc_values_supported: [String.t()] | :undefined,
          userinfo_signing_alg_values_supported: [String.t()] | :undefined,
          userinfo_encryption_alg_values_supported: [String.t()] | :undefined,
          userinfo_encryption_enc_values_supported: [String.t()] | :undefined,
          request_object_signing_alg_values_supported: [String.t()] | :undefined,
          request_object_encryption_alg_values_supported: [String.t()] | :undefined,
          request_object_encryption_enc_values_supported: [String.t()] | :undefined,
          token_endpoint_auth_methods_supported: [String.t()],
          token_endpoint_auth_signing_alg_values_supported: [String.t()] | :undefined,
          display_values_supported: [String.t()] | :undefined,
          claim_types_supported: [:normal | :aggregated | :distributed],
          claims_supported: [String.t()] | :undefined,
          service_documentation: :uri_string.uri_string() | :undefined,
          claims_locales_supported: [String.t()] | :undefined,
          ui_locales_supported: [String.t()] | :undefined,
          claims_parameter_supported: boolean(),
          request_parameter_supported: boolean(),
          request_uri_parameter_supported: boolean(),
          require_request_uri_registration: boolean(),
          op_policy_uri: :uri_string.uri_string() | :undefined,
          op_tos_uri: :uri_string.uri_string() | :undefined,
          revocation_endpoint: :uri_string.uri_string() | :undefined,
          revocation_endpoint_auth_methods_supported: [String.t()],
          revocation_endpoint_auth_signing_alg_values_supported: [String.t()] | :undefined,
          introspection_endpoint: :uri_string.uri_string() | :undefined,
          introspection_endpoint_auth_methods_supported: [String.t()],
          introspection_endpoint_auth_signing_alg_values_supported: [String.t()] | :undefined,
          code_challenge_methods_supported: [String.t()] | :undefined,
          end_session_endpoint: :uri_string.uri_string() | :undefined,
          require_pushed_authorization_requests: boolean(),
          pushed_authorization_request_endpoint: :uri_string.uri_string() | :undefined,
          authorization_response_iss_parameter_supported: boolean(),
          authorization_signing_alg_values_supported: [String.t()] | :undefined,
          authorization_encryption_alg_values_supported: [String.t()] | :undefined,
          authorization_encryption_enc_values_supported: [String.t()] | :undefined,
          dpop_signing_alg_values_supported: [String.t()] | :undefined,
          require_signed_request_object: boolean(),
          mtls_endpoint_aliases: %{binary() => :uri_string.uri_string()},
          tls_client_certificate_bound_access_tokens: boolean(),
          extra_fields: %{String.t() => term()}
        }

  @doc """
  Load OpenID Configuration

  ## Examples

      iex> {:ok, {
      ...>   %ProviderConfiguration{issuer: "https://accounts.google.com"},
      ...>   _expiry
      ...> }} = Oidcc.ProviderConfiguration.load_configuration("https://accounts.google.com")
  """
  @doc since: "3.0.0"
  @spec load_configuration(
          issuer :: :uri_string.uri_string(),
          opts :: :oidcc_provider_configuration.opts()
        ) ::
          {:ok, {configuration :: t(), expiry :: pos_integer()}}
          | {:error, :oidcc_provider_configuration.error()}
  def load_configuration(issuer, opts \\ %{}) do
    with {:ok, {configuration, expiry}} <-
           :oidcc_provider_configuration.load_configuration(issuer, opts) do
      {:ok, {record_to_struct(configuration), expiry}}
    end
  end

  @doc """
  Load JWKs

  ## Examples

      iex> {:ok, {%JOSE.JWK{}, _expiry}} =
      ...>   Oidcc.ProviderConfiguration.load_jwks("https://www.googleapis.com/oauth2/v3/certs")
  """
  @doc since: "3.0.0"
  @spec load_jwks(
          jwks_uri :: :uri_string.uri_string(),
          opts :: :oidcc_provider_configuration.opts()
        ) ::
          {:ok, {jwks :: JOSE.JWK.t(), expiry :: pos_integer()}}
          | {:error, :oidcc_provider_configuration.error()}
  def load_jwks(jwks_uri, opts \\ %{}) do
    with {:ok, {jwks, expiry}} <-
           :oidcc_provider_configuration.load_jwks(jwks_uri, opts) do
      {:ok, {JOSE.JWK.from_record(jwks), expiry}}
    end
  end

  @doc """
  Decode JSON into OpenID configuration

  ## Examples

      iex> {:ok, {{~c"HTTP/1.1",200, ~c"OK"}, _headers, body}} =
      ...>   :httpc.request("https://accounts.google.com/.well-known/openid-configuration")
      ...>
      ...> decoded_json = body |> to_string() |> JOSE.decode()
      ...>
      ...> {:ok, %ProviderConfiguration{issuer: "https://accounts.google.com"}} =
      ...>   Oidcc.ProviderConfiguration.decode_configuration(decoded_json)
  """
  @doc since: "3.0.0"
  @spec decode_configuration(configuration :: map(), opts :: :oidcc_provider_configuration.opts()) ::
          {:ok, t()} | {:error, :oidcc_provider_configuration.error()}
  def decode_configuration(configuration, opts \\ %{}) do
    with {:ok, configuration} <-
           :oidcc_provider_configuration.decode_configuration(configuration, opts) do
      {:ok, record_to_struct(configuration)}
    end
  end
end
