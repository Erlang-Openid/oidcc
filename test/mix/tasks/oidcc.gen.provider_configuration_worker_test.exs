defmodule Mix.Tasks.Oidcc.Gen.ProviderConfigurationWorkerTest do
  use ExUnit.Case, async: true
  import Igniter.Test

  test "adds configuration if the file doesn't exist yet" do
    test_project()
    |> Igniter.compose_task("oidcc.gen.provider_configuration_worker", [
      "--name",
      "Test.Provider",
      "--issuer",
      "https://accounts.google.com"
    ])
    |> assert_creates("config/runtime.exs", """
    import Config

    config :test, Test.Provider,
      issuer: System.get_env("TEST_PROVIDER_ISSUER", "https://accounts.google.com")
    """)
  end

  test "patches configuration if the file exists" do
    test_project(
      files: %{
        "config/runtime.exs" => """
        import Config

        config :logger, level: :info
        """
      }
    )
    |> Igniter.compose_task("oidcc.gen.provider_configuration_worker", [])
    |> assert_has_patch("config/runtime.exs", """
    1 1   |import Config
    2 2   |
      3 + |config :test, Test.OpenIDProvider, issuer: System.fetch_env!("TEST_OPEN_ID_PROVIDER_ISSUER")
    3 4   |config :logger, level: :info
    4 5   |
    """)
  end

  test "adds worker to application supervision tree" do
    test_project()
    |> Igniter.compose_task("oidcc.gen.provider_configuration_worker", ["--name", "Test.Provider"])
    |> assert_creates("lib/test/application.ex", """
    defmodule Test.Application do
      @moduledoc false

      use Application

      @impl true
      def start(_type, _args) do
        children = [
          {Oidcc.ProviderConfiguration.Worker,
           %{name: Test.Provider, issuer: Application.fetch_env!(:test, Test.Provider)[:issuer]}}
        ]

        opts = [strategy: :one_for_one, name: Test.Supervisor]
        Supervisor.start_link(children, opts)
      end
    end
    """)
  end

  test "keeps existing worker in application supervision tree" do
    test_project(
      files: %{
        "config/runtime.exs" => """
        import Config
        config :test, Test.Provider, issuer: System.fetch_env!("TEST_PROVIDER_ISSUER")
        """,
        "lib/test/application.ex" => """
        defmodule Test.Application do
          @moduledoc false

          use Application

          @impl true
          def start(_type, _args) do
            children = [
              {Oidcc.ProviderConfiguration.Worker,
               %{name: Test.Provider, issuer: Application.fetch_env!(:test, Test.Provider)[:issuer]}}
            ]

            opts = [strategy: :one_for_one, name: Test.Supervisor]
            Supervisor.start_link(children, opts)
          end
        end
        """
      }
    )
    |> Igniter.compose_task("oidcc.gen.provider_configuration_worker", ["--name", "Test.Provider"])
    |> assert_unchanged(["config/runtime.exs", "lib/test/application.ex"])
  end
end
