module ScannerExtensions
  class BaseExtension
    attr_reader   :defaults
    attr_accessor :type
    attr_accessor :scan_level
    attr_accessor :general_object_type
    attr_accessor :extension_type
    attr_accessor :modifier
    attr_accessor :optional
    attr_accessor :splitted
    attr_accessor :factor
    attr_accessor :fork
    attr_accessor :fictive
    attr_accessor :detect
    attr_accessor :point
    attr_accessor :detect_type
    attr_accessor :can_use_ipv6
    attr_accessor :disabled
    attr_accessor :components

    def all_components
      %i[rechecker fast]
    end

    def components
      @components || all_components
    end

    def disabled
      @disabled ||= false
    end

    def scan_level
      @scan_level || :classic
    end

    def modifier
      @modifier || :none
    end

    def optional
      @optional || false
    end

    def splitted
      @splitted || false
    end

    def fork
      @fork || false
    end

    def factor
      @factor || 50
    end

    def fictive
      @fictive || false
    end

    def queue_type
      @queue_type || :normal
    end

    def can_use_ipv6
      @can_use_ipv6 || false
    end
  end
end
