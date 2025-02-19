defmodule Mix.Tasks.Oidcc.Gen.ProviderConfigurationWorker do
  @example """
  mix oidcc.gen.provider_configuration_worker \\
    --name MyApp.OpenIDProvider \\
    --issuer https://accounts.google.com \
  """

  @shortdoc "Generate an OpenID Connect provider configuration worker"
  if !Code.ensure_loaded?(Igniter) do
    @shortdoc "#{@shortdoc} | Install `igniter` to use"
  end

  @moduledoc """
  #{@shortdoc}

  Adds an `Oidcc.ProviderConfiguration.Worker` to your application and
  configures it via the `runtime.exs` configuration file.

  ## Example

  ```bash
  #{@example}
  ```

  ## Options

  * `--name` or `-n` - The name of the provider configuration worker
  * `--issuer` or `-i` - The issuer of the provider
  """

  if Code.ensure_loaded?(Igniter) do
    use Igniter.Mix.Task

    alias Igniter.Code.Module
    alias Igniter.Project.Application
    alias Igniter.Project.Config

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        # dependencies to add
        adds_deps: [],
        # dependencies to add and call their associated installers, if they exist
        installs: [],
        # An example invocation
        example: @example,
        # Accept additional arguments that are not in your schema
        # Does not guarantee that, when composed, the only options you get are the ones you define
        extra_args?: false,
        # A list of environments that this should be installed in, only relevant if this is an installer.
        only: nil,
        # a list of positional arguments, i.e `[:file]`
        positional: [],
        # Other tasks your task composes using `Igniter.compose_task`, passing in the CLI argv
        # This ensures your option schema includes options from nested tasks
        composes: [],
        # `OptionParser` schema
        schema: [name: :string, issuer: :string],
        # CLI aliases
        aliases: [n: :name, i: :issuer]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter, argv) do
      # extract positional arguments according to `positional` above
      {_arguments, argv} = positional_args!(argv)
      # extract options according to `schema` and `aliases` above
      options = setup_options(argv, igniter)

      igniter
      |> configure_issuer(options)
      |> add_application_worker(options)
    end

    defp setup_options(argv, igniter) do
      argv
      |> options!()
      |> Keyword.update(
        :name,
        Module.module_name(igniter, "OpenIDProvider"),
        &Module.parse/1
      )
      |> Keyword.put(:app_name, Igniter.Project.Application.app_name(igniter))
    end

    defp configure_issuer(igniter, options) do
      env_prefix =
        options[:name] |> Macro.underscore() |> String.upcase() |> String.replace("/", "_")

      config =
        case Keyword.fetch(options, :issuer) do
          {:ok, issuer} ->
            quote do
              [issuer: System.get_env(unquote("#{env_prefix}_ISSUER"), unquote(issuer))]
            end

          :error ->
            quote do
              [issuer: System.fetch_env!(unquote("#{env_prefix}_ISSUER"))]
            end
        end

      Config.configure_new(
        igniter,
        "runtime.exs",
        options[:app_name],
        [options[:name]],
        {:code, config}
      )
    end

    defp add_application_worker(igniter, options) do
      Application.add_new_child(
        igniter,
        {Oidcc.ProviderConfiguration.Worker,
         {:code,
          quote do
            %{
              name: unquote(options[:name]),
              issuer:
                Application.fetch_env!(unquote(options[:app_name]), unquote(options[:name]))[
                  :issuer
                ]
            }
          end}}
      )
    end
  else
    use Mix.Task

    @impl Mix.Task
    def run(_argv) do
      Mix.shell().error("""
      The task 'oidcc.gen.provider_configuration_worker' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
