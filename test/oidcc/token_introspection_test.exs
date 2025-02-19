# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.TokenIntrospectionTest do
  use ExUnit.Case

  import Mock

  alias Oidcc.ClientContext
  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token
  alias Oidcc.TokenIntrospection

  doctest TokenIntrospection

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

  describe inspect(&TokenIntrospection.introspect/3) do
    test_with_mock "works", %{}, :oidcc_http_util, [:passthrough],
      request: fn :post,
                  {"https://my.provider/introspection", _headers,
                   ~c"application/x-www-form-urlencoded", "token=access_token"},
                  _telemetry_opts,
                  _http_opts ->
        {:ok,
         {{:json,
           %{
             "active" => true,
             "client_id" => "client_id"
           }}, []}}
      end do
      client_context =
        ClientContext.from_manual(
          @example_metadata,
          @example_jwks,
          "client_id",
          "client_secret"
        )

      assert {:ok, %TokenIntrospection{active: true}} =
               TokenIntrospection.introspect(
                 %Token{
                   id: %Token.Id{
                     token: "id_token",
                     claims: %{}
                   },
                   access: %Token.Access{token: "access_token", expires: :undefined},
                   refresh: :none,
                   scope: ["profile", "openid"]
                 },
                 client_context
               )
    end
  end
end
