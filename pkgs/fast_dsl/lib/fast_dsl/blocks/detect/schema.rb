module FastDsl
  module Blocks
    class Detect
      # describe detect block schema
      module Schema
        def schema
          html_objs = %w[js attr attribute href tag]

          html_schema = Dry::Validation.Schema do
            configure { predicates(FastDsl::Schema::Predicates) }

            each do
              str? & included_in?(['html']) | schema do
                required('html').each do
                  str? & included_in?(html_objs) | schema do
                    html_objs.each { |obj| optional(obj) { regexp? } }
                  end
                end
              end
            end
          end

          Dry::Validation.Schema do
            configure { predicates(FastDsl::Schema::Predicates) }

            optional('oob').each(
              included_in?: %w[dns]
            )

            optional('response').each do
              str? & included_in?(%w[headers body]) | schema do
                optional('headers').value(:regexp_or_array_of_regexp_hash?)

                optional('status').value(:int_or_string?)

                optional('body').value(:regexp_or_array?)

                validate(detect_response_body: 'body') do |body|
                  !body || FastDsl::Schema::Predicates.regexp?(body) || html_schema.call(body).success?
                end

                instance_eval(&FastDsl::Schema::Predicates.ensure_values('body', %w[html], :detect_response_body))
              end
            end

            instance_eval(
              &FastDsl::Schema::Predicates.ensure_values(
                'response',
                %w[headers status body],
                :detect_response
              )
            )
          end
        end
      end
    end
  end
end
