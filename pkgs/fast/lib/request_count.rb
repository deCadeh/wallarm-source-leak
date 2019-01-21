module RequestCount
  module_function

  def count
    Thread.current[:request_count] || 0
  end

  def count=(val)
    Thread.current[:request_count] = val
  end
end
