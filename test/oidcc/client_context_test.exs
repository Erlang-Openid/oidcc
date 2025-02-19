# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ClientContextTest do
  use ExUnit.Case, async: true

  alias Oidcc.ClientContext

  doctest ClientContext

  describe inspect(&ProviderConfiguration.from_configuration_worker/3) do
    test "works" do
      pid =
        start_supervised!(
          {Oidcc.ProviderConfiguration.Worker,
           %{issuer: "https://accounts.google.com", name: __MODULE__.GoogleProvider}}
        )

      assert {:ok, %Oidcc.ClientContext{}} =
               Oidcc.ClientContext.from_configuration_worker(
                 __MODULE__.GoogleProvider,
                 "client_id",
                 "client_Secret"
               )

      assert {:ok, %Oidcc.ClientContext{}} =
               Oidcc.ClientContext.from_configuration_worker(
                 pid,
                 "client_id",
                 "client_Secret"
               )

      assert {:error, :provider_not_ready} =
               Oidcc.ClientContext.from_configuration_worker(
                 __MODULE__.InvalidProvider,
                 "client_id",
                 "client_Secret"
               )
    end
  end

  describe inspect(&ProviderConfiguration.from_manual/4) do
    test "works" do
      {:ok, {configuration, _expiry}} =
        Oidcc.ProviderConfiguration.load_configuration("https://login.salesforce.com")

      {:ok, {jwks, _expiry}} =
        Oidcc.ProviderConfiguration.load_jwks(configuration.jwks_uri)

      assert %Oidcc.ClientContext{} =
               Oidcc.ClientContext.from_manual(
                 configuration,
                 jwks,
                 "client_id",
                 "client_Secret"
               )
    end
  end
end
