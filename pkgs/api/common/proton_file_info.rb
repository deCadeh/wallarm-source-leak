require 'proton'

class ProtonFileInfo
  attr_reader :type, :format, :version, :checksum

  TYPES = { 1 => 'proton.db', 2 => 'lom', 3 => 'selectors' }

  def initialize( key_file, file, validate = true)
    data = ""
    file_checker = Proton::FileChecker.new(key_file)

    if !validate || file_checker.check(file)
       data = File.read( file, 16).to_s rescue ""
       data.force_encoding "ASCII-8BIT"
    end

    info = data.unpack( "NNN")
    @type    = TYPES[info[0]]
    @format  = info[1]
    @version = info[2]

    @checksum = data[12, 4].unpack( "N").first rescue nil
  end
end
