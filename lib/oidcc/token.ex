# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Token do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :request_token, :start],
    description: "Emitted at the start of requesting a code token",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :request_token, :stop],
    description: "Emitted at the end of requesting a code token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :request_token, :exception],
    description: "Emitted at the end of requesting a code token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :refresh_token, :start],
    description: "Emitted at the start of refreshing a token",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :refresh_token, :stop],
    description: "Emitted at the end of refreshing a token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :refresh_token, :exception],
    description: "Emitted at the end of refreshing a token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :jwt_profile_token, :start],
    description: "Emitted at the start of exchanging a JWT profile token",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :jwt_profile_token, :stop],
    description: "Emitted at the end of exchanging a JWT profile token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :jwt_profile_token, :exception],
    description: "Emitted at the end of exchanging a JWT profile token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :client_credentials, :start],
    description: "Emitted at the start of requesting a client credentials token",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :client_credentials, :stop],
    description: "Emitted at the end of requesting a client credentials token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :client_credentials, :exception],
    description: "Emitted at the end of requesting a client credentials token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  @moduledoc """
  Facilitate OpenID Code/Token Exchanges

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :token,
    record_name: :oidcc_token,
    hrl: "include/oidcc_token.hrl"

  alias Oidcc.ClientContext
  alias Oidcc.Token.Access
  alias Oidcc.Token.Id
  alias Oidcc.Token.Refresh

  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          id: Id.t() | none,
          access: Access.t() | none,
          refresh: Refresh.t() | none,
          scope: :oidcc_scope.scopes()
        }

  @doc """
  retrieve the token using the authcode received before and directly validate
  the result.

  the authcode was sent to the local endpoint by the OpenId Connect provider,
  using redirects

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.retrieve_token/5`.

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
      ...> # Get auth_code from redirect
      ...> auth_code = "auth_code"
      ...>
      ...> Oidcc.Token.retrieve(
      ...>   auth_code,
      ...>   client_context,
      ...>   %{redirect_uri: "https://my.server/return"}
      ...> )
      ...> # => {:ok, %Oidcc.Token{}}

  """
  @doc since: "3.0.0"
  @spec retrieve(
          auth_code :: String.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token.retrieve_opts()
        ) ::
          {:ok, t()} | {:error, :oidcc_token.error()}
  def retrieve(auth_code, client_context, opts) do
    client_context = ClientContext.struct_to_record(client_context)

    auth_code
    |> :oidcc_token.retrieve(client_context, opts)
    |> normalize_token_response()
  end

  @doc """
  Validate the JARM response, returning the valid claims as a map.

  the response was sent to the local endpoint by the OpenId Connect provider,
  using redirects

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
      ...> # Get auth_code from redirect
      ...> response = "JWT"
      ...>
      ...> Oidcc.Token.validate_jarm(
      ...>   response,
      ...>   client_context,
      ...>   %{}
      ...> )
      ...> # => {:ok, %{"code" => auth_code}}

  """
  @doc since: "3.2.0"
  @spec validate_jarm(
          response :: String.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token.validate_jarm_opts()
        ) ::
          {:ok, :oidcc_jwt_util.claims()} | {:error, :oidcc_token.error()}
  def validate_jarm(response, client_context, opts) do
    client_context = ClientContext.struct_to_record(client_context)

    :oidcc_token.validate_jarm(response, client_context, opts)
  end

  @doc """
  Refresh Token

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.refresh_token/5`.

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
      ...> # Get refresh_token from redirect
      ...> refresh_token = "refresh_token"
      ...>
      ...> Oidcc.Token.refresh(
      ...>   refresh_token,
      ...>   client_context,
      ...>   %{expected_subject: "sub"}
      ...> )
      ...> # => {:ok, %Oidcc.Token{}}

  """
  @doc since: "3.0.0"
  @spec refresh(
          refresh_token :: String.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token.refresh_opts()
        ) :: {:ok, t()} | {:error, :oidcc_token.error()}
  @spec refresh(
          token :: t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token.refresh_opts_no_sub()
        ) :: {:ok, t()} | {:error, :oidcc_token.error()}
  def refresh(token, client_context, opts) do
    token =
      case token do
        token when is_binary(token) -> token
        %__MODULE__{} = token -> struct_to_record(token)
      end

    client_context = ClientContext.struct_to_record(client_context)

    token
    |> :oidcc_token.refresh(client_context, opts)
    |> normalize_token_response()
  end

  @doc """
  Validate ID Token

  Usually the id token is validated using `retrieve/3`.
  If you get the token passed from somewhere else, this function can validate it.

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
      ...> #Get IdToken from somewhere
      ...> id_token = "id_token"
      ...>
      ...> Oidcc.Token.validate_id_token(id_token, client_context, :any)
      ...> # => {:ok, %{"sub" => "sub", ... }}

  """
  @doc since: "3.0.0"
  @spec validate_id_token(
          id_token :: String.t(),
          client_context :: ClientContext.t(),
          nonce :: String.t() | any
        ) :: {:ok, :oidcc_jwt_util.claims()} | {:error, :oidcc_token.error()}
  def validate_id_token(id_token, client_context, nonce),
    do:
      :oidcc_token.validate_id_token(
        id_token,
        ClientContext.struct_to_record(client_context),
        nonce
      )

  @doc """
  Validate JWT

  Validates a generic JWT (such as an access token) from the given provider.
  Useful if the issuer is shared between multiple applications, and the access token
  generated for a user at one client is used to validate their access at another client.

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
      ...> #Get JWT from Authorization header
      ...> jwt = "jwt"
      ...>
      ...> opts = %{
      ...>   signing_algs: client_context.provider_configuration.id_token_signing_alg_values_supported
      ...> }
      ...>
      ...> Oidcc.Token.validate_jwt(jwt, client_context, opts)
      ...> # => {:ok, %{"sub" => "sub", ... }}

  """
  @doc since: "3.0.0"
  @spec validate_jwt(
          jwt :: String.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token.validate_jwt_opts()
        ) :: {:ok, :oidcc_jwt_util.claims()} | {:error, :oidcc_token.error()}
  def validate_jwt(jwt, client_context, opts),
    do:
      :oidcc_token.validate_jwt(
        jwt,
        ClientContext.struct_to_record(client_context),
        opts
      )

  @doc """
  Retrieve JSON Web Token (JWT) Profile Token

  See https://datatracker.ietf.org/doc/html/rfc7523#section-4

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.jwt_profile_token/6`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "JWT Profile Test",
      ...>     "client_secret"
      ...>   )
      ...>
      ...> %{"key" => key, "keyId" => kid, "userId" => subject} = "JWT_PROFILE"
      ...>   |> System.fetch_env!()
      ...>   |> JOSE.decode()
      ...>
      ...> jwk = JOSE.JWK.from_pem(key)
      ...>
      ...> {:ok, %Oidcc.Token{}} =
      ...>   Oidcc.Token.jwt_profile(
      ...>     subject,
      ...>     client_context,
      ...>     jwk,
      ...>     %{scope: ["openid", "urn:zitadel:iam:org:project:id:zitadel:aud"], kid: kid}
      ...>   )

  """
  @doc since: "3.0.0"
  @spec jwt_profile(
          subject :: String.t(),
          client_context :: ClientContext.t(),
          jwk :: JOSE.JWK.t(),
          opts :: :oidcc_token.jwt_profile_opts()
        ) :: {:ok, t()} | {:error, :oidcc_token.error()}
  def jwt_profile(subject, client_context, jwk, opts) do
    jwk = JOSE.JWK.to_record(jwk)
    client_context = ClientContext.struct_to_record(client_context)

    subject
    |> :oidcc_token.jwt_profile(client_context, jwk, opts)
    |> normalize_token_response()
  end

  @doc """
  Retrieve Client Credential Token

  See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.client_credentials_token/4`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     System.fetch_env!("CLIENT_CREDENTIALS_CLIENT_ID"),
      ...>     System.fetch_env!("CLIENT_CREDENTIALS_CLIENT_SECRET")
      ...>   )
      ...>
      ...> {:ok, %Oidcc.Token{}} =
      ...>   Oidcc.Token.client_credentials(
      ...>     client_context,
      ...>     %{scope: ["openid"]}
      ...>   )

  """
  @doc since: "3.0.0"
  @spec client_credentials(
          client_context :: ClientContext.t(),
          opts :: :oidcc_token.client_credentials_opts()
        ) :: {:ok, t()} | {:error, :oidcc_token.error()}
  def client_credentials(client_context, opts),
    do:
      client_context
      |> ClientContext.struct_to_record()
      |> :oidcc_token.client_credentials(opts)
      |> normalize_token_response()

  @doc false
  @spec normalize_token_response(
          response :: {:ok, :oidcc_token.t()} | {:error, :oidcc_token.error()}
        ) ::
          {:ok, t()} | {:error, :oidcc_token.error()}
  def normalize_token_response(response)
  def normalize_token_response({:ok, token}), do: {:ok, record_to_struct(token)}

  def normalize_token_response({:error, {:none_alg_used, token}}),
    do: {:error, {:none_alg_used, record_to_struct(token)}}

  def normalize_token_response({:error, reason}), do: {:error, reason}

  @impl Oidcc.RecordStruct
  def record_to_struct(record) do
    record
    |> super()
    |> update_if_not_none(:id, &Id.record_to_struct/1)
    |> update_if_not_none(:access, &Access.record_to_struct/1)
    |> update_if_not_none(:refresh, &Refresh.record_to_struct/1)
  end

  @impl Oidcc.RecordStruct
  def struct_to_record(struct) do
    struct
    |> update_if_not_none(:id, &Id.struct_to_record/1)
    |> update_if_not_none(:access, &Access.struct_to_record/1)
    |> update_if_not_none(:refresh, &Refresh.struct_to_record/1)
    |> super()
  end

  defp update_if_not_none(map, key, callback) do
    Map.update!(map, key, fn
      :none -> :none
      other -> callback.(other)
    end)
  end
end
