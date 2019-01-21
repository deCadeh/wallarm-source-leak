module Exclude
  module_function

  def web_money_lmi_hash(req)
    points = [
      [[:post], [:form_urlencoded, 'LMI_HASH']],
      [[:post], [:multipart, 'LMI_HASH']],
      [[:get, 'LMI_HASH']]
    ]
    for point in points do
      begin
        entry = req[point]
        if entry
          entry.value = 'stripped'
        end
      rescue => e
      end
    end
  end
end

