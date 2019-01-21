module FastDsl
  # DSL is loading from yaml or json; but all semantic validation is here
  module Schema
    SCHEMA = Dry::Validation.Schema do
      configure { config.messages_file = "#{__dir__}/schema/errors.yaml" }

      configure { predicates(Schema::Predicates) }

      optional('generate').schema(FastDsl::Blocks::Generate.schema)

      optional('match').value(:hash?, :regexp_hash?)

      optional('modify').value(:hash?, :str_hash?)

      optional('detect').each do
        str? & included_in?(%w[response oob]) | schema(FastDsl::Blocks::Detect.schema)
      end

      required('meta-info').schema(FastDsl::Blocks::MetaInfo.schema)

      instance_eval(&Schema::Predicates.ensure_values('detect', %w[response oob], :detect))
    end

    module_function

    def validate!(hash)
      res = SCHEMA.call(hash)
      return if res.success?

      raise ArgumentError, res.messages
    end
  end
end
