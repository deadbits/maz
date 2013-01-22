require 'mongo'
require 'pp'
require 'yaml'

module Maz
  class Environment
    def load_config
      if not File.exists?(File.absolute_path(File.dirname($0)) + '/../../conf/config.yml')
        error_msg("configuration file config.yml was not found!")
        return false
      end
      conf_path = File.absolute_path(File.dirname($0)) + '/../../conf/config.yml'
      info_msg("reading configuration file: #{conf_path}")
      raw_config = File.read(conf_path)
      @config = YAML.load(raw_config)
    end

    def start_database
      host = ENV['MONGO_RUBY_DRIVER_HOST'] || 'localhost'
      port = ENV['MONGO_RUBY_DRIVER_PORT'] || Client::DEFAULT_PORT
      info_msg("connecting to mongodb @ #{host}:#{port}")
      @mongo = Mongo::Client.new(host, port, :safe => true)
      db = @mongo.db('maz-storage')
      samples_coll = db.create_collection('samples')
      storage_coll = db.create_collection('reports')
      admin = @mongo['admin']

      colls = [samples_coll, storage_coll]
      info_msg("validating database collections")
      colls.each do |coll|
        info = db.validate_collection(coll.name)
        info_msg("")

      samples_info = db.validate_collection(samples_coll.name)
      storage_info = db.validate_collection(storage_coll.name)
      puts "[info] validated mongodb collections: "
      puts "\t #{samples_info['ok']}"
      puts "\t #{storage_info['ok']}"
      puts "\t "

info = db.validate_collection(coll.name)
puts "valid = #{info['ok']}"
puts info['result']



