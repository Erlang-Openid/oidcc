# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc do
  @moduledoc """
  OpenID Connect High Level Interface

  ## Setup

      {:ok, _pid} =
        Oidcc.ProviderConfiguration.Worker.start_link(%{
        issuer: "https://accounts.google.com",
        name: MyApp.GoogleConfigProvider
      })

  or via a supervisor

      Supervisor.init([
        {Oidcc.ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
      ], strategy: :one_for_one)

  ## Global Configuration

  * `max_clock_skew` (default `0`) - Maximum allowed clock skew for JWT
    `exp` / `nbf` validation, in seconds
  """
  @moduledoc since: "3.0.0"

  @doc """
  Create Auth Redirect URL

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>   issuer: "https://accounts.google.com"
      ...> })
      ...>
      ...> {:ok, _redirect_uri} =
      ...>   Oidcc.create_redirect_url(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret",
      ...>     %{redirect_uri: "https://my.server/return"}
      ...>   )

  """
  @doc since: "3.0.0"
  @spec create_redirect_url(
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_authorization.opts() | :oidcc_client_context.opts()
        ) ::
          {:ok, :uri_string.uri_string()}
          | {:error, :oidcc_client_context.error()}
  def create_redirect_url(provider_configuration_name, client_id, client_secret, opts),
    do: :oidcc.create_redirect_url(provider_configuration_name, client_id, client_secret, opts)

  @doc """
  retrieve the token using the authcode received before and directly validate
  the result.

  the authcode was sent to the local endpoint by the OpenId Connect provider,
  using redirects

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://api.login.yahoo.com"
      ...>   })
      ...>
      ...> # Get auth_code from redirect
      ...> auth_code = "auth_code"
      ...>
      ...> Oidcc.retrieve_token(
      ...>   auth_code,
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret",
      ...>   %{redirect_uri: "https://my.server/return"}
      ...> )
      ...> # => {:ok, %Oidcc.Token{}}

  """
  @doc since: "3.0.0"
  @spec retrieve_token(
          auth_code :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.retrieve_opts() | :oidcc_client_context.opts()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def retrieve_token(auth_code, provider_configuration_name, client_id, client_secret, opts),
    do:
      auth_code
      |> :oidcc.retrieve_token(
        provider_configuration_name,
        client_id,
        client_secret,
        opts
      )
      |> Oidcc.Token.normalize_token_response()

  @doc """
  Refresh Token

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://api.login.yahoo.com"
      ...>   })
      ...>
      ...> # Get refresh_token from redirect
      ...> refresh_token = "refresh_token"
      ...>
      ...> Oidcc.refresh_token(
      ...>   refresh_token,
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret",
      ...>   %{expected_subject: "sub_from_initial_id_token"}
      ...> )
      ...> # => {:ok, %Oidcc.Token{}}

  """
  @doc since: "3.0.0"
  @spec refresh_token(
          refresh_token :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.refresh_opts() | :oidcc_client_context.opts()
        ) :: {:ok, Oidcc.Token.t()} | {:error, :oidcc_token.error()}
  @spec refresh_token(
          token :: Oidcc.Token.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.refresh_opts_no_sub() | :oidcc_client_context.opts()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def refresh_token(token, provider_configuration_name, client_id, client_secret, opts \\ %{}) do
    token =
      case token do
        %Oidcc.Token{} = token -> Oidcc.Token.struct_to_record(token)
        token when is_binary(token) -> token
      end

    token
    |> :oidcc.refresh_token(
      provider_configuration_name,
      client_id,
      client_secret,
      opts
    )
    |> Oidcc.Token.normalize_token_response()
  end

  @doc """
  Introspect the given access token

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://api.login.yahoo.com"
      ...>   })
      ...>
      ...> Oidcc.introspect_token(
      ...>   "access_token",
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret"
      ...> )
      ...> # => {:ok, %Oidcc.TokenIntrospection{}}

  """
  @doc since: "3.0.0"
  @spec introspect_token(
          access_token :: String.t() | Oidcc.Token.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token_introspection.opts() | :oidcc_client_context.opts()
        ) ::
          {:ok, Oidcc.TokenIntrospection.t()}
          | {:error, :oidcc_client_context.error() | :oidcc_token_introspection.error()}
  def introspect_token(
        token,
        provider_configuration_name,
        client_id,
        client_secret,
        opts \\ %{}
      ) do
    token =
      case token do
        %Oidcc.Token{} = token -> Oidcc.Token.struct_to_record(token)
        token when is_binary(token) -> token
      end

    with {:ok, introspection} <-
           :oidcc.introspect_token(
             token,
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      {:ok, Oidcc.TokenIntrospection.record_to_struct(introspection)}
    end
  end

  @doc """
  Load userinfo for the given token

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://api.login.yahoo.com"
      ...>   })
      ...>
      ...> # Get access_token from Oidcc.Token.retrieve/3
      ...> access_token = "access_token"
      ...>
      ...> Oidcc.retrieve_userinfo(
      ...>   access_token,
      ...>   pid,
      ...>   "client_id",
      ...>   "client_secret",
      ...>   %{expected_subject: "sub"}
      ...> )
      ...> # => {:ok, %{"sub" => "sub"}}

  """
  @doc since: "3.0.0"
  @spec retrieve_userinfo(
          token :: Oidcc.Token.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_userinfo.retrieve_opts_no_sub() | :oidcc_client_context.opts()
        ) :: {:ok, :oidcc_jwt_util.claims()} | {:error, :oidcc_userinfo.error()}
  @spec retrieve_userinfo(
          access_token :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_userinfo.retrieve_opts() | :oidcc_client_context.opts()
        ) ::
          {:ok, :oidcc_jwt_util.claims()}
          | {:error, :oidcc_client_context.error() | :oidcc_userinfo.error()}
  def retrieve_userinfo(token, provider_configuration_name, client_id, client_secret, opts \\ %{}) do
    token =
      case token do
        %Oidcc.Token{} = token -> Oidcc.Token.struct_to_record(token)
        token when is_binary(token) -> token
      end

    :oidcc.retrieve_userinfo(token, provider_configuration_name, client_id, client_secret, opts)
  end

  @doc """
  Retrieve JSON Web Token (JWT) Profile Token

  https://datatracker.ietf.org/doc/html/rfc7523#section-4

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> %{"key" => key, "keyId" => kid, "userId" => subject} = "JWT_PROFILE"
      ...>   |> System.fetch_env!()
      ...>   |> JOSE.decode()
      ...>
      ...> jwk = JOSE.JWK.from_pem(key)
      ...>
      ...> {:ok, %Oidcc.Token{}} =
      ...>   Oidcc.jwt_profile_token(
      ...>     subject,
      ...>     pid,
      ...>     "JWT Profile Test",
      ...>     "client_secret",
      ...>     jwk,
      ...>     %{scope: ["openid", "urn:zitadel:iam:org:project:id:zitadel:aud"], kid: kid}
      ...>   )

  """
  @doc since: "3.0.0"
  @spec jwt_profile_token(
          subject :: String.t(),
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          jwk :: JOSE.JWK.t(),
          opts :: :oidcc_token.jwt_profile_opts() | :oidcc_client_context.opts()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def jwt_profile_token(subject, provider_configuration_name, client_id, client_secret, jwk, opts) do
    jwk = JOSE.JWK.to_record(jwk)

    subject
    |> :oidcc.jwt_profile_token(
      provider_configuration_name,
      client_id,
      client_secret,
      jwk,
      opts
    )
    |> Oidcc.Token.normalize_token_response()
  end

  @doc """
  Retrieve Client Credential Token

  See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> {:ok, %Oidcc.Token{}} =
      ...>   Oidcc.client_credentials_token(
      ...>     pid,
      ...>     System.fetch_env!("CLIENT_CREDENTIALS_CLIENT_ID"),
      ...>     System.fetch_env!("CLIENT_CREDENTIALS_CLIENT_SECRET"),
      ...>     %{scope: ["openid"]}
      ...>   )

  """
  @doc since: "3.0.0"
  @spec client_credentials_token(
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          client_secret :: String.t(),
          opts :: :oidcc_token.client_credentials_opts() | :oidcc_client_context.opts()
        ) ::
          {:ok, Oidcc.Token.t()} | {:error, :oidcc_client_context.error() | :oidcc_token.error()}
  def client_credentials_token(provider_configuration_name, client_id, client_secret, opts),
    do:
      provider_configuration_name
      |> :oidcc.client_credentials_token(
        client_id,
        client_secret,
        opts
      )
      |> Oidcc.Token.normalize_token_response()

  @doc """
  Create Initiate URI for Relaying Party initiated Logout

  See [https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout]

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://erlef-test-w4a8z2.zitadel.cloud"
      ...>   })
      ...>
      ...> # Get access_token from Oidcc.Token.retrieve/3
      ...> token = "token"
      ...>
      ...> {:ok, _redirect_uri} = Oidcc.initiate_logout_url(
      ...>   token,
      ...>   pid,
      ...>   "client_id"
      ...> )

  """
  @doc since: "3.0.0"
  @spec initiate_logout_url(
          token :: id_token | Oidcc.Token.t() | :undefined,
          provider_configuration_name :: GenServer.name(),
          client_id :: String.t(),
          opts :: :oidcc_logout.initiate_url_opts() | :oidcc_client_context.opts()
        ) ::
          {:ok, :uri_string.uri_string()}
          | {:error, :oidcc_client_context.error() | :oidcc_logout.error()}
        when id_token: String.t()
  def initiate_logout_url(
        token,
        provider_configuration_name,
        client_id,
        opts \\ %{}
      ) do
    token =
      case token do
        %Oidcc.Token{} = token -> Oidcc.Token.struct_to_record(token)
        token when is_binary(token) -> token
        :undefined -> :undefined
      end

    :oidcc.initiate_logout_url(
      token,
      provider_configuration_name,
      client_id,
      opts
    )
  end
end
