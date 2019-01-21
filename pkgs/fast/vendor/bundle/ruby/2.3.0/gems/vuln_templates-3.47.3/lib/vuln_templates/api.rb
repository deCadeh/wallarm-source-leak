module VulnTemplates
  module_function

  def templates
    index = VulnTemplates::DataLoader.tmpls.index
    res   = []
    DataLoader.tmpls.list_id.sort.each do |id|
      res << {
        :id     => id,
        :name   => index[id],
        :params => DataLoader.tmpls.required_params[id]
      }
    end
    return res
  end

  def template_by_id(id)
    res = templates.select{|i| i[:id]==id}[0]
    raise UnknownTemplate, id if res.nil?
    return res
  end

  def views
    index = VulnTemplates::DataLoader.views.index
    res   = []
    DataLoader.views.list_id.sort.each do |id|
      res << {
        :id     => id,
        :name   => index[id],
        :params => DataLoader.views.required_params[id]
      }
    end
    return res
  end

  def view_by_id(id)
    res = views.select{|i| i[:id]==id}[0]
    raise UnknownView, id if res.nil?
    return res
  end
end

