# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule OidccTest do
  use ExUnit.Case

  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token

  doctest Oidcc

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

  describe inspect(&Oidcc.create_redirect_url/4) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
        )

      assert {:ok, _redirect_uri} =
               Oidcc.create_redirect_url(
                 pid,
                 "client_id",
                 "client_secret",
                 %{redirect_uri: "https://my.server/return"}
               )
    end
  end

  describe inspect(&Oidcc.retrieve_token/5) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
        )

      assert {:error, {:http_error, 400, _body}} =
               Oidcc.retrieve_token(
                 "auth_code",
                 pid,
                 "client_id",
                 "client_secret",
                 %{redirect_uri: "https://my.server/return"}
               )
    end
  end

  describe inspect(&Oidcc.refresh_token/5) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
        )

      assert {:error, {:http_error, 401, _body}} =
               Oidcc.refresh_token(
                 %Token{
                   id: %Token.Id{
                     token: "id_token",
                     claims: %{"sub" => "sub"}
                   },
                   access: %Token.Access{token: "access_token", expires: :undefined},
                   refresh: %Token.Refresh{token: "refresh_token"},
                   scope: ["profile", "openid"]
                 },
                 pid,
                 "client_id",
                 "client_secret",
                 %{redirect_uri: "https://my.server/return"}
               )
    end
  end

  describe inspect(&Oidcc.introspect_token/5) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://api.login.yahoo.com"}}
        )

      assert {:error, {:http_error, 400, _body}} =
               Oidcc.introspect_token(
                 %Token{
                   id: %Token.Id{
                     token: "id_token",
                     claims: %{"sub" => "sub"}
                   },
                   access: %Token.Access{token: "access_token", expires: :undefined},
                   refresh: %Token.Refresh{token: "refresh_token"},
                   scope: ["profile", "openid"]
                 },
                 pid,
                 "client_id",
                 "client_secret"
               )
    end
  end

  describe inspect(&Oidcc.retrieve_userinfo/5) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://api.login.yahoo.com"}}
        )

      assert {:error, {:http_error, 401, _body}} =
               Oidcc.retrieve_userinfo(
                 %Token{
                   id: %Token.Id{
                     token: "id_token",
                     claims: %{"sub" => "sub"}
                   },
                   access: %Token.Access{token: "access_token", expires: :undefined},
                   refresh: %Token.Refresh{token: "refresh_token"},
                   scope: ["profile", "openid"]
                 },
                 pid,
                 "client_id",
                 "client_secret"
               )
    end
  end

  describe inspect(&Oidcc.jwt_profile_token/4) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://erlef-test-w4a8z2.zitadel.cloud"}}
        )

      %{"key" => key, "keyId" => kid, "userId" => subject} = JOSE.decode(@jwt_profile)

      jwk = JOSE.JWK.from_pem(key)

      assert {:ok, %Token{}} =
               Oidcc.jwt_profile_token(
                 subject,
                 pid,
                 "JWT Profile Test",
                 "client_secret",
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

      assert {:ok, %Token{}} =
               Oidcc.client_credentials_token(
                 pid,
                 @client_credentials_client_id,
                 @client_credentials_client_secret,
                 %{scope: ["openid"]}
               )
    end
  end

  describe inspect(&Oidcc.initiate_logout_url/4) do
    test "works" do
      pid =
        start_supervised!(
          {ProviderConfiguration.Worker, %{issuer: "https://erlef-test-w4a8z2.zitadel.cloud"}}
        )

      assert {:ok, _redirect_uri} =
               Oidcc.initiate_logout_url(
                 "id_token",
                 pid,
                 "client_id"
               )
    end
  end
end
