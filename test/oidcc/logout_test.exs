# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.LogoutTest do
  use ExUnit.Case, async: true

  alias Oidcc.Logout

  doctest Logout

  describe inspect(&Logout.create_redirect_url/3) do
    test "works" do
      pid =
        start_supervised!(
          {Oidcc.ProviderConfiguration.Worker,
           %{issuer: "https://erlef-test-w4a8z2.zitadel.cloud"}}
        )

      {:ok, client_context} =
        Oidcc.ClientContext.from_configuration_worker(
          pid,
          "client_id",
          :unauthenticated
        )

      assert {:ok, _redirect_uri} =
               Logout.initiate_url(
                 "token",
                 client_context,
                 %{post_logout_redirect_uri: "https://my.server/return"}
               )
    end
  end
end
