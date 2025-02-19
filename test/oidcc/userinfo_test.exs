# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.UserinfoTest do
  use ExUnit.Case, async: false

  import Mock

  alias Oidcc.ClientContext
  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token
  alias Oidcc.Userinfo

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

  doctest Userinfo

  describe inspect(&Userinfo.retrieve/3) do
    test_with_mock "works", %{}, :oidcc_http_util, [:passthrough],
      request: fn :get, {"https://my.provider/userinfo", _headers}, _telemetry_opts, _http_opts ->
        {:ok,
         {{:json,
           %{
             "sub" => "sub"
           }}, []}}
      end do
      client_context =
        ClientContext.from_manual(
          @example_metadata,
          @example_jwks,
          "client_id",
          "client_secret"
        )

      assert {:ok, %{"sub" => "sub"}} =
               Userinfo.retrieve(
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
                 %{expected_subject: "sub"}
               )
    end
  end
end
