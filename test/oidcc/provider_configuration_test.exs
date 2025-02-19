# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ProviderConfigurationTest do
  use ExUnit.Case, async: true

  alias Oidcc.ProviderConfiguration

  doctest ProviderConfiguration

  describe inspect(&ProviderConfiguration.load_configuration/2) do
    test "works" do
      assert {:ok, {%ProviderConfiguration{issuer: "https://accounts.google.com"}, _expiry}} =
               ProviderConfiguration.load_configuration("https://accounts.google.com", %{})
    end
  end

  describe inspect(&ProviderConfiguration.load_jwks/2) do
    test "works" do
      assert {:ok, {%JOSE.JWK{}, _expiry}} =
               ProviderConfiguration.load_jwks("https://www.googleapis.com/oauth2/v3/certs", %{})
    end
  end

  describe inspect(&ProviderConfiguration.decode_configuration/1) do
    test "works" do
      assert {:ok, %ProviderConfiguration{issuer: "https://my.provider"}} =
               :oidcc
               |> Application.app_dir("priv/test/fixtures/example-metadata.json")
               |> File.read!()
               |> JOSE.decode()
               |> ProviderConfiguration.decode_configuration()
    end
  end
end
