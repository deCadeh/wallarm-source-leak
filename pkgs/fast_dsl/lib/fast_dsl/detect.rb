require 'dry-validation'

require_relative './oob_dns'
require_relative './helpers'
require_relative './baseline'

require_relative './schema/predicates'

require_relative './detect/context'
require_relative './detect/payload_check'
require_relative './detect/vuln'

require_relative './blocks/generate'
require_relative './blocks/match'
require_relative './blocks/modify'
require_relative './blocks/detect'
require_relative './blocks/meta_info'

require_relative './schema'

module FastDsl
  # This class is running single FAST check
  class Detect
    def initialize(hash)
      Schema.validate!(hash)

      @match     = Blocks::Match.new(hash['match'])
      @modify    = Blocks::Modify.new(hash['modify'])
      @generate  = Blocks::Generate.new(hash['generate'])
      @detect    = Blocks::Detect.new(hash['detect'])
      @meta_info = Blocks::MetaInfo.new(hash['meta-info'])

      @all = [@match, @modify, @generate, @detect]
    end

    def applicable?(baseline)
      @all.all? do |block|
        block.respond_to?(:applicable?) ? block.applicable?(baseline) : true
      end
    end

    def run(baseline)
      ctx = FastDsl::Detect::Context.new(baseline: baseline)

      @all.each do |block|
        next unless block.respond_to?(:run)

        block.run(ctx)
      end

      ctx.meta_info = @meta_info

      ctx
    end
  end
end
