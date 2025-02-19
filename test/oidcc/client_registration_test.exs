# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.ClientRegistrationTest do
  use ExUnit.Case, async: true

  alias Oidcc.ClientRegistration

  doctest ClientRegistration

  describe inspect(&ClientRegistration.register/3) do
    test "works" do
      {:ok, {provider_configuration, _expiry}} =
        Oidcc.ProviderConfiguration.load_configuration("https://accounts.google.com")

      assert {:error, :registration_not_supported} =
               Oidcc.ClientRegistration.register(
                 provider_configuration,
                 %Oidcc.ClientRegistration{
                   redirect_uris: ["https://your.application.com/oidcc/callback"]
                 }
               )
    end
  end
end
