module SysInfo
  INFODIR = '/usr/share/wallarm-common/engine'

  @info = nil

  def self.load_info!
    return unless @info.nil?

    @info = {}

    Dir.glob(File.join(INFODIR, '*')).sort.each do |f|
      begin
        data = File.read(f)
        data.lines.each do |line|
          key, value = line.strip.split(/\s*=\s*/, 2)
          @info[key.to_sym] = value
        end
      rescue
        # ignore
      end
    end
  end

  def self.engine_type
    load_info!
    @info[:engine_type] || 'unknown'
  end

  def self.nginx_group
    load_info!
    @info[:nginx_group]
  end
end
