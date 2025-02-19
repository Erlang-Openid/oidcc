# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ProviderConfiguration.WorkerTest do
  use ExUnit.Case, async: true

  alias Oidcc.ProviderConfiguration
  alias Oidcc.ProviderConfiguration.Worker

  doctest Worker

  describe inspect(&Worker.start_link/1) do
    test "works" do
      start_supervised!(
        {Worker, %{issuer: "https://accounts.google.com", name: __MODULE__.GoogleProvider}}
      )
    end
  end

  describe inspect(&Worker.get_provider_configuration/1) do
    test "works" do
      pid =
        start_supervised!(
          {Worker, %{issuer: "https://accounts.google.com", name: __MODULE__.GoogleProvider}}
        )

      assert %ProviderConfiguration{issuer: "https://accounts.google.com"} =
               Worker.get_provider_configuration(pid)
    end
  end

  describe inspect(&Worker.get_jwks/1) do
    test "works" do
      start_supervised!(
        {Worker, %{issuer: "https://accounts.google.com", name: __MODULE__.GoogleProvider}}
      )

      assert %JOSE.JWK{} =
               Worker.get_jwks(__MODULE__.GoogleProvider)
    end
  end

  describe inspect(&Worker.refresh_configuration/1) do
    test "works" do
      pid =
        start_supervised!(
          {Worker, %{issuer: "https://accounts.google.com", name: __MODULE__.GoogleProvider}}
        )

      assert :ok = Worker.refresh_configuration(pid)
    end
  end

  describe inspect(&Worker.refresh_jwks/1) do
    test "works" do
      pid =
        start_supervised!(
          {Worker, %{issuer: "https://accounts.google.com", name: __MODULE__.GoogleProvider}}
        )

      assert :ok = Worker.refresh_jwks(pid)
    end
  end

  describe inspect(&Worker.refresh_jwks_for_unknown_kid/2) do
    test "works" do
      pid =
        start_supervised!(
          {Worker, %{issuer: "https://accounts.google.com", name: __MODULE__.GoogleProvider}}
        )

      assert :ok = Worker.refresh_jwks_for_unknown_kid(pid, "kid")
    end
  end
end
