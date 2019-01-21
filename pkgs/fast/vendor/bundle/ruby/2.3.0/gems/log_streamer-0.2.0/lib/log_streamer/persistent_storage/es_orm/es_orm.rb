# rubocop:disable all
class EsOrm
  MAX_LIMIT = 1000

  BaseError            = Class.new(RuntimeError)
  TooLargeRequestError = Class.new(BaseError)
  InvalidFilterError   = Class.new(BaseError)
  IndexMissingError    = Class.new(BaseError)

  @@fields      = {}
  @@filter_by   = []
  @@index       = []
  @@process     = {}
  @@format      = {}
  @@index_limit = 64
  @@type        = nil
  @@es          = nil
  @@additional  = {
    allow_no_indices: true,
    ignore_unavailable: true
  }

  @@time_format = nil

  class << self
    def set_connection(es)
      @@es = es
    end

    def es_type(type)
      @@type = type
    end

    def es_time_format(format)
      @@time_format = format
    end

    def es_default_time_processer(params)
      name, step = params.values_at(:name, :step)

      send :es_process, name, lambda { |k, v|
        from = v[0]
        to = v[1]

        # Gen indices
        cur = from
        while cur < to
          @index += [Time.at(cur).strftime(@@time_format)]
          cur    += step
          if @index.size > @@index_limit
            raise TooLargeRequestError, 'Number of indicies is too big'
          end
        end

        @index += [Time.at(cur).strftime(@@time_format)]

        # Process conditions
        [
          gte(k, from),
          lte(k, to)
        ]
      }
    end

    def es_field(name, params = {})
      type = params[:type] || nil
      @@fields[name.to_s] = type
      send :define_method, name do
        @params[name]
      end
    end

    def es_fields(*args)
      args.map { |f| es_field(f) }
    end

    def es_filter_by(*args)
      args.each do |field|
        if @@fields.key? field.to_s
          @@filter_by << field.to_s
        else
          raise "Invalid field '#{field}'"
        end
      end
    end

    def es_additional_force(v)
      @@additional = v
    end

    def es_additional(k, v)
      @@additional[k] = v
    end

    def es_index(index)
      @@index = [index].flatten
    end

    def es_process(name, block)
      @@process[name] = block
    end

    def es_format(name, block)
      @@format[name] = block
    end

    def es_invalid_filter?(params)
      params.each do |k, v|
        k = k.to_s
        k = k[1..-1] if k[0] == '!'
        unless @@filter_by.include? k.to_s
          return "Nonexistent filter field '#{k}'"
        end

        case @@fields[k.to_s]
        when :int
          return "Field '#{k}' must be integer" unless v.is_a? Integer
        when :time_interval
          if !v.is_a?(Array) || v.size != 2 || !v[0].is_a?(Integer) || !v[1].is_a?(Integer)
            return "Field '#{k}' must be time_interval"
          end
        else
          if v.is_a?(Array)
            v.each do |item|
              return "Field '#{k}' must be array of strings" unless item.is_a? String
            end
          else
            return "Field '#{k}' must be string" unless v.is_a? String
          end
        end
      end

      false
    end
  end

  def self.create(params)
    res = new(params)
    res.save
  end

  def save
    request = {
      index: Time.at(@params[:time]).strftime(@@time_format),
      type:  @@type,
      body:  @params
    }

    @@es.index(request)
    self
  end

  def initialize(params)
    @params = {}
    params.each do |name, value|
      next unless @@fields.keys.include? name.to_s
      @params[name.to_sym] = if @@format[name.to_sym]
                               @@format[name.to_sym].call(value)
                             else
                               value
                             end
    end
  end

  def to_h
    res = {}
    @params.each { |k, v| res[k.to_s] = v }
    res
  end

  def self.filter(opt = {})
    if (res = es_invalid_filter?(opt))
      raise InvalidFilterError, res
    end

    params = {
      klass:       self,
      filter:      opt,
      index:       @@index,
      fields:      @@fields,
      process:     @@process,
      additional:  @@additional,
      index_limit: @@index_limit,
      es:          @@es
    }

    EsQuery.new(params)
  end

  private

  class EsQuery
    def initialize(params)
      @klass       = params[:klass]
      @filter      = params[:filter]
      @index       = params[:index].dup
      @fields      = params[:fields]
      @process     = params[:process]
      @additional  = params[:additional]
      @index_limit = params[:index_limit]
      @es          = params[:es]

      @limit       = nil
      @offset      = nil
      @order_field = nil
      @order_order = nil
      @order_params = []
    end

    def order_by(field, order = :asc)
      raise "Invalid order '#{order}'" unless %i[asc desc].include? order
      @order_params << [field, order]
      @order_field = field
      @order_order = order
      self
    end

    def limit(n)
      @limit = n
      self
    end

    def offset(n)
      @offset = n
      self
    end

    def query
      final = {}
      body  = {}

      body[:from]  = @offset || 0
      body[:size]  = @limit  || EsOrm::MAX_LIMIT

      if body[:size] > EsOrm::MAX_LIMIT
        raise TooLargeRequestError, 'Limit is too big'
      end
      body[:sort] = []

      @order_params.each do |op|
        body[:sort] << { op[0] => { order: op[1] } }
      end

      final[:body] = body

      conditions     = []
      not_conditions = []
      @filter.each do |k, v|
        k = k.to_s
        negotiation = false
        if k[0] == '!'
          k = k[1..-1]
          array = not_conditions
          negotiation = true
        end
        raise "Unknow parameter '#{k}'" unless @fields.keys.include? k.to_s
        k = k.to_sym
        item = if @process[k]
                 instance_exec k, v, &@process[k]
               else
                 [default_conditon(k, v)]
               end
        if negotiation
          not_conditions += item
        else
          conditions     += item
        end
      end
      body[:query] = query_by_conditions(conditions, not_conditions)
      if @index.empty?
        raise IndexMissingError, 'Unable to determine index from filter'
      end
      final[:index] = @index.uniq.sort
      final.merge!(@additional)

      if final[:index].size > @index_limit
        raise TooLargeRequestError, 'Index count is too big'
      end

      final
    end

    def all
      result = @es.search(query)['hits']['hits']
      result.map { |r| @klass.new({ 'id' => r['_id'] }.merge(r['_source'])) }
    end

    def count
      q = query
      q.body.delete(:size, :offset, :sort)
      res = @es.count(q)
      res['count'].to_i
    end

    private

    def gte(k, v)
      { range: { k => { gte: v } } }
    end

    def lte(k, v)
      { range: { k => { lte: v } } }
    end

    def gt(k, v)
      { range: { k => { gt: v } } }
    end

    def lt(k, v)
      { range: { k => { lt: v } } }
    end

    def default_conditon(k, v)
      if v.is_a?(Array)
        { terms: { k => v } }
      else
        { match: { k => v } }
      end
    end

    def query_by_conditions(conditions, not_conditions)
      if conditions.empty? && not_conditions.empty?
        { match_all: {} }
      else
        {
          bool:  {
            must:     conditions,
            must_not: not_conditions
          }
        }
      end
    end
  end
end
