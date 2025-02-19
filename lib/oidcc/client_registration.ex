# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ClientRegistration do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :register_client, :start],
    description: "Emitted at the start of registering the client",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string()}"
  })

  telemetry_event(%{
    event: [:oidcc, :register_client, :stop],
    description: "Emitted at the end of registering the client",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string()}"
  })

  telemetry_event(%{
    event: [:oidcc, :register_client, :exception],
    description: "Emitted at the end of registering the client",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string()}"
  })

  @moduledoc """
  Dynamic Client Registration Utilities

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :metadata,
    record_name: :oidcc_client_registration,
    record_type_module: :oidcc_client_registration,
    record_type_name: :t,
    hrl: "include/oidcc_client_registration.hrl"

  alias Oidcc.ClientRegistration.Response
  alias Oidcc.ProviderConfiguration

  @typedoc """
  Client Metadata Struct

  See https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata and
  https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata
  """
  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          redirect_uris: [:uri_string.uri_string()],
          response_types: [String.t()] | :undefined,
          grant_types: [String.t()] | :undefined,
          application_type: :web | :native,
          contacts: [String.t()] | :undefined,
          client_name: String.t() | :undefined,
          logo_uri: :uri_string.uri_string() | :undefined,
          client_uri: :uri_string.uri_string() | :undefined,
          policy_uri: :uri_string.uri_string() | :undefined,
          tos_uri: :uri_string.uri_string() | :undefined,
          jwks: :jose_jwk.key() | :undefined,
          jwks_uri: :uri_string.uri_string() | :undefined,
          sector_identifier_uri: :uri_string.uri_string() | :undefined,
          subject_type: :pairwise | :public | :undefined,
          id_token_signed_response_alg: String.t() | :undefined,
          id_token_encrypted_response_alg: String.t() | :undefined,
          id_token_encrypted_response_enc: String.t() | :undefined,
          userinfo_signed_response_alg: String.t() | :undefined,
          userinfo_encrypted_response_alg: String.t() | :undefined,
          userinfo_encrypted_response_enc: String.t() | :undefined,
          request_object_signing_alg: String.t() | :undefined,
          request_object_encryption_alg: String.t() | :undefined,
          request_object_encryption_enc: String.t() | :undefined,
          token_endpoint_auth_method: String.t(),
          token_endpoint_auth_signing_alg: String.t() | :undefined,
          default_max_age: pos_integer() | :undefined,
          require_auth_time: boolean(),
          default_acr_values: [String.t()] | :undefined,
          initiate_login_uri: :uri_string.uri_string() | :undefined,
          request_uris: [:uri_string.uri_string()] | :undefined,
          post_logout_redirect_uris: [:uri_string.uri_string()] | :undefined,
          require_pushed_authorization_requests: boolean(),
          dpop_bound_access_tokens: boolean(),
          extra_fields: %{String.t() => term()}
        }

  @doc """
  Register Client

  ## Examples

      iex> {:ok, {provider_configuration, _expiry}} =
      ...>   Oidcc.ProviderConfiguration.load_configuration("https://accounts.google.com")
      ...>
      ...> Oidcc.ClientRegistration.register(
      ...>   provider_configuration,
      ...>   %Oidcc.ClientRegistration{
      ...>     redirect_uris: ["https://your.application.com/oidcc/callback"]
      ...>   },
      ...>   %{initial_access_token: "optional token you got from the provider"}
      ...> )
      ...> # {:ok, %Oidcc.ClientRegistration.Response{
      ...> #   client_id: client_id,
      ...> #   client_secret: client_secret
      ...> # }}

  """
  @doc since: "3.0.0"
  @spec register(provider_configuration, registration, opts) ::
          {:ok, Response.t()} | {:error, :oidcc_client_registration.error()}
        when provider_configuration: ProviderConfiguration.t(),
             registration: t(),
             opts: :oidcc_client_registration.opts()
  def register(provider_configuration, registration, opts \\ %{}) do
    provider_configuration = ProviderConfiguration.struct_to_record(provider_configuration)
    registration = struct_to_record(registration)

    with {:ok, response} <-
           :oidcc_client_registration.register(provider_configuration, registration, opts) do
      {:ok, Response.record_to_struct(response)}
    end
  end

  @impl Oidcc.RecordStruct
  def record_to_struct(record) do
    record
    |> super()
    |> update_if_not_undefined(:jwks, &JOSE.JWK.from_record/1)
  end

  @impl Oidcc.RecordStruct
  def struct_to_record(struct) do
    struct
    |> update_if_not_undefined(:jwks, &JOSE.JWK.to_record/1)
    |> super()
  end

  defp update_if_not_undefined(map, key, callback) do
    Map.update!(map, key, fn
      :undefined -> :undefined
      other -> callback.(other)
    end)
  end
end
