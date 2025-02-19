# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.AuthorizationTest do
  use ExUnit.Case, async: true

  alias Oidcc.Authorization

  doctest Authorization

  describe inspect(&Authorization.create_redirect_url/2) do
    test "works" do
      pid =
        start_supervised!(
          {Oidcc.ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
        )

      {:ok, client_context} =
        Oidcc.ClientContext.from_configuration_worker(
          pid,
          "client_id",
          "client_secret"
        )

      assert {:ok, _redirect_uri} =
               Authorization.create_redirect_url(
                 client_context,
                 %{redirect_uri: "https://my.server/return"}
               )
    end
  end
end
