require 'fileutils'
require 'hashie/mash'
require 'proton'
require 'wallarm/common/proton_file_info'
require 'wallarm/common/sys_info'

class NodeDataSyncer
  FORMATS = {
    'proton.db' => Proton::DB_VERSION,
    'lom'       => Proton::LOM_VERSION }

  DEFAULTS = {
    enabled: true,
    key_file: '/etc/wallarm/license.key',
    protondb: '/etc/wallarm/proton.db',
    lom: '/etc/wallarm/lom',
    interval: 600,
    rand_delay: 300,
    timeout: 900,
    owner: 'root',
    group: 'wallarm',
    mode: 0640 }

  attr_accessor :api
  attr_reader :conf, :logger

  def initialize(args = {})
    @api = args[:api]
    @logger = args[:logger] || Logger.new(nil)

    configure!(args[:opts] || {})
  end

  def enabled?
    conf.enabled
  end

  def registered?
    !@api.nil?
  end

  def sync
    return true unless enabled?
    return false unless registered?

    pid = fork do
      logger.debug 'Syncnode started'

      if sync_no_fork
        exit 0
      else
        exit 1
      end
    end

    watchdog = Thread.new do
      sleep conf.timeout
      logger.warn 'Syncnode timeout reached'
      Process.kill 'TERM', pid
      sleep 5
      Process.kill 'KILL', pid
    end

    _, rc = Process.wait2 pid

    watchdog.kill

    if rc.nil?
      logger.error 'Unknown syncnode exit code'
      return false
    end

    unless rc.success?
      logger.error "Syncnode exited with code #{rc.exitstatus}" if rc.exited?
      logger.error "Syncnode killed by signal #{rc.termsig}" if rc.signaled?
      return false
    end

    true
  end

  def sync_no_fork
    begin
      license = api.get('/v2/license')
      current = File.read(conf.key_file) rescue nil
      if license != current
        store(license, path: conf.key_file)
        logger.info 'License key was updated'
      else
        fix_file_permissions(path: conf.key_file)
      end
    rescue Wallarm::API2::Error => e
      logger.error "Can't fetch license key: #{e}"
      return false
    end

    rc = true

    begin
      if sync_file('proton.db', path: conf.protondb,
                                owner: conf.owner,
                                group: conf.group,
                                mode: conf.mode)
        yield 'proton.db' if block_given?
        logger.info 'Proton.db was updated'
      else
        logger.debug 'Proton.db was not changed'
      end
    rescue => e
      rc = false
      logger.error "Can't sync proton.db: #{e}"
    end

    begin
      if sync_file('lom', path: conf.lom,
                          owner: conf.owner,
                          group: conf.group,
                          mode: conf.mode)
        yield 'lom' if block_given?
        logger.info 'Lom was updated'
      else
        logger.debug 'Lom was not changed'
      end
    rescue => e
      rc = false
      logger.error "Can't sync lom: #{e}"
    end

    return rc
  end

  def sync_loop
    next_sync = 0
    errors = 0

    loop do
      time = Time.now.to_i

      unless enabled? && time > next_sync
        sleep 1
        next
      end

      begin
        sync

        next_sync = time + conf.interval + rand(conf.rand_delay)
        errors = 0
        logger.debug 'syncnode success!'
      rescue => e
        errors += 1
        next_sync = time + 60 + rand(60)
        logger.error "#{errors} last syncs failed: #{e}" if errors % 10 == 1
      end
    end
  end

  # returns:
  #   true if file was changed
  #   false if file was not changed
  #   raise exception on error
  #
  def sync_file(type, args)
    file = args[:path]
    validate = args.fetch(:validate, true)

    fileinfo = ProtonFileInfo.new(conf.key_file, file, validate)
    data = fetch(type, fileinfo)

    if data.nil?
      fix_file_permissions(args)
      return false
    end

    tmpfile = File.join( File.dirname(file), ".#{File.basename(file)}.new")
    store(data, args.merge(:path => tmpfile))
    data = nil
    GC.start

    if validate && !file_checker.check(tmpfile)
      raise "bad file, error message: `#{file_checker.error_msg}'"
    end

    File.rename( tmpfile, file)

    true
  ensure
    File.unlink tmpfile rescue nil
  end

  private

  def with_env(name)
    value = ENV[name]
    yield value if value
  end

  def with_bool_env(name)
    with_env(name) do |value|
      case value.downcase
      when 'true', 'yes', '1'
        yield true
      else
        yield false
      end
    end
  end

  def configure!(opts = {})
    @conf = Hashie::Mash.new(DEFAULTS)

    conf.group = SysInfo.nginx_group unless SysInfo.nginx_group.nil?

    with_bool_env('WALLARM_SYNCNODE')       { |v| conf.enabled = v }
    with_env('WALLARM_SYNCNODE_INTERVAL')   { |v| conf.interval = v.to_i }
    with_env('WALLARM_SYNCNODE_RAND_DELAY') { |v| conf.rand_delay = v.to_i }
    with_env('WALLARM_SYNCNODE_TIMEOUT')    { |v| conf.timeout = v.to_i }
    with_env('WALLARM_SYNCNODE_OWNER')      { |v| conf.owner = v }
    with_env('WALLARM_SYNCNODE_GROUP')      { |v| conf.group = v }
    with_env('WALLARM_SYNCNODE_MODE')       { |v| conf.mode = v.to_i(8) }

    opts.delete_if{ |_,v| v.nil? }
    conf.merge! opts
  end

  def file_checker
    Proton::FileChecker.new(conf.key_file)
  end

  # returns: data, nil or exception
  def fetch(type, fileinfo)
    if fileinfo.type == type
      current = {
          :format   => fileinfo.format,
          :version  => fileinfo.version,
          :checksum => fileinfo.checksum }
    end

    api.node_data(type, FORMATS[type], current)
  end

  def store(data, args)
    File.open(args[:path], "wb") do |f|
      uid = args[:owner] || conf.owner
      uid = Etc.getpwnam( uid.to_s).uid unless Integer == uid

      gid = args[:group] || conf.group
      gid = Etc.getgrnam( gid.to_s).gid unless Integer == gid

      f.chown( uid, gid)
      f.chmod args[:mode] || conf.mode

      f.write data
    end
  end

  def fix_file_permissions(args)
    uid = args[:owner] || conf.owner
    uid = Etc.getpwnam( uid.to_s).uid unless Integer == uid

    gid = args[:group] || conf.group
    gid = Etc.getgrnam( gid.to_s).gid unless Integer == gid

    mode = args[:mode] || conf.mode

    File.chown( uid, gid, args[:path])
    File.chmod( mode, args[:path])
  end
end
