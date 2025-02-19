# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.TokenTest do
  use ExUnit.Case, async: false

  import Mock

  alias Oidcc.ClientContext
  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token

  {:ok, example_metadata} =
    :oidcc
    |> Application.app_dir("priv/test/fixtures/example-metadata.json")
    |> File.read!()
    |> JOSE.decode()
    |> ProviderConfiguration.decode_configuration()

  @example_metadata example_metadata
  @example_jwks :oidcc
                |> Application.app_dir("priv/test/fixtures/jwk.pem")
                |> JOSE.JWK.from_pem_file()

  %{
    "clientId" => client_credentials_client_id,
    "clientSecret" => client_credentials_client_secret
  } =
    :oidcc
    |> Application.app_dir("priv/test/fixtures/zitadel-client-credentials.json")
    |> File.read!()
    |> JOSE.decode()

  @client_credentials_client_id client_credentials_client_id
  @client_credentials_client_secret client_credentials_client_secret

  @jwt_profile :oidcc
               |> Application.app_dir("priv/test/fixtures/zitadel-jwt-profile.json")
               |> File.read!()

  doctest Token

  setup_all do
    # Used in doctests
    System.put_env("CLIENT_CREDENTIALS_CLIENT_ID", @client_credentials_client_id)
    System.put_env("CLIENT_CREDENTIALS_CLIENT_SECRET", @client_credentials_client_secret)
    System.put_env("JWT_PROFILE", @jwt_profile)

    # Allow minimal clock skew for Zitadel
    Application.put_env(:oidcc, :max_clock_skew, 5)

    :ok
  end

  describe inspect(&Token.retrieve/3) do
    test_with_mock "works", %{}, :oidcc_http_util, [],
      request: fn :post,
                  {"https://my.provider/token", _headers, ~c"application/x-www-form-urlencoded",
                   _body},
                  _telemetry_opts,
                  _http_opts ->
        {_jws, token} =
          @example_jwks
          |> JOSE.JWT.sign(
            %{"alg" => "RS256"},
            JOSE.JWT.from(%{
              "iss" => "https://my.provider",
              "sub" => "sub",
              "aud" => "client_id",
              "iat" => :erlang.system_time(:second),
              "exp" => :erlang.system_time(:second) + 10
            })
          )
          |> JOSE.JWS.compact()

        {:ok,
         {{:json,
           %{
             "access_token" => "access_token",
             "token_type" => "Bearer",
             "id_token" => token,
             "scope" => "profile openid",
             "refresh_token" => "refresh_token"
           }}, []}}
      end do
      client_context =
        ClientContext.from_manual(
          @example_metadata,
          @example_jwks,
          "client_id",
          "client_secret"
        )

      assert {:ok,
              %Token{
                id: %Token.Id{
                  token: _token,
                  claims: %{
                    "aud" => "client_id",
                    "exp" => _exp,
                    "iat" => _iat,
                    "iss" => "https://my.provider",
                    "sub" => "sub"
                  }
                },
                access: %Token.Access{token: "access_token", expires: :undefined},
                refresh: %Token.Refresh{token: "refresh_token"},
                scope: ["profile", "openid"]
              }} =
               Token.retrieve(
                 "auth_code",
                 client_context,
                 %{redirect_uri: "https://my.server/return"}
               )
    end
  end

  describe inspect(&Token.refresh/3) do
    test_with_mock "works", %{}, :oidcc_http_util, [],
      request: fn :post,
                  {"https://my.provider/token", _headers, ~c"application/x-www-form-urlencoded",
                   _body},
                  _telemetry_opts,
                  _http_opts ->
        {_jws, token} =
          @example_jwks
          |> JOSE.JWT.sign(
            %{"alg" => "RS256"},
            JOSE.JWT.from(%{
              "iss" => "https://my.provider",
              "sub" => "sub",
              "aud" => "client_id",
              "iat" => :erlang.system_time(:second),
              "exp" => :erlang.system_time(:second) + 10
            })
          )
          |> JOSE.JWS.compact()

        {:ok,
         {{:json,
           %{
             "access_token" => "access_token",
             "token_type" => "Bearer",
             "id_token" => token,
             "scope" => "profile openid"
           }}, []}}
      end do
      client_context =
        ClientContext.from_manual(
          @example_metadata,
          @example_jwks,
          "client_id",
          "client_secret"
        )

      assert {:ok,
              %Token{
                id: %Token.Id{
                  token: _token,
                  claims: %{
                    "sub" => "sub"
                  }
                },
                access: %Token.Access{token: "access_token", expires: :undefined},
                refresh: :none,
                scope: ["profile", "openid"]
              }} =
               Token.refresh(
                 %Token{
                   id: %Token.Id{
                     token: "id_token",
                     claims: %{"sub" => "sub"}
                   },
                   access: %Token.Access{token: "access_token", expires: :undefined},
                   refresh: %Token.Refresh{token: "refresh_token"},
                   scope: ["profile", "openid"]
                 },
                 client_context,
                 %{redirect_uri: "https://my.server/return"}
               )
    end
  end

  describe inspect(&Token.jwt_profile/4) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://erlef-test-w4a8z2.zitadel.cloud"}}
        )

      {:ok, client_context} =
        ClientContext.from_configuration_worker(
          pid,
          "JWT Profile Test",
          "client_secret"
        )

      %{"key" => key, "keyId" => kid, "userId" => subject} = JOSE.decode(@jwt_profile)

      jwk = JOSE.JWK.from_pem(key)

      assert {:ok, %Token{}} =
               Token.jwt_profile(
                 subject,
                 client_context,
                 jwk,
                 %{scope: ["openid", "urn:zitadel:iam:org:project:id:zitadel:aud"], kid: kid}
               )
    end
  end

  describe inspect(&Oidcc.client_credentials_token/2) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://erlef-test-w4a8z2.zitadel.cloud"}}
        )

      {:ok, client_context} =
        ClientContext.from_configuration_worker(
          pid,
          @client_credentials_client_id,
          @client_credentials_client_secret
        )

      assert {:ok, %Token{}} =
               Oidcc.Token.client_credentials(
                 client_context,
                 %{scope: ["openid"]}
               )
    end
  end
end
