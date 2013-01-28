#!/usr/bin/env ruby
##
# Malware Analysis Zoo
# https://github.com/ohdae/maz
##
# MAZ is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MAZ is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MAZ.  If not, see <http://www.gnu.org/licenses/>.
##

require 'readline'
require 'term/ansicolor'
require 'yaml'
require 'pp'
include Term::ANSIColor

module Maz
  class Core

    def initialize
      @@Database = Maz::Database.new
      status("checking MAZ environment ...")
      unless File.directory?("#{ENV['HOME']}/maz")
        puts "This looks like your first time running MAZ. Starting setup ..."
        status("creating environment directories ...")
        Dir.mkdir("#{ENV['HOME']}/maz")
        Dir.mkdir("#{ENV['HOME']}/maz/samples")
        Dir.mkdir("#{ENV['HOME']}/maz/logs")
        info("environment created.")
      end
      info("environment ok.\n")
    end

    def shutdown
      status("shutting down MAZ ...")
      exit
    end

    #def load_config(file)
    #  unless File.exists?(file) = false
    #    error("configuration file #{file} was not found")
    #    return false
    #  end
    #  path = File.absolute_path(File.dirname($0))+"#{file}"
    #  raw = File.read(path)
    #  @config = YAML.load(raw)
    #  return true
    #end

    def text_report(sample)
      pbwhite("\n\t[ Sample Information ]")
      puts "File Name:\t#{sample[:file_name]}"
      puts "File Type:\t#{sample[:file_type]}"
      puts "File Size:\t#{sample[:file_size]}"
      puts " Location:\t#{sample[:location]}"
      puts "Submitted:\t#{sample[:time]}"
      puts " MD5 Hash:\t#{sample[:md5_hash]}"
      puts "SHA1 Hash:\t#{sample[:sha1_hash]}"
      unless sample[:shadow] == nil
        pbwhite("\t[ ShadowServer Results ]")
        puts "First Seen:\t#{sample[:shadow][:first]}"
        puts " Last Seen:\t#{sample[:shadow][:last]}"
        puts " File Type:\t#{sample[:shadow][:type]}"
        pbwhite("\t[ Anti-Virus ]")
        sample[:shadow][:avres].each { |av| pp "#{av}"}
        puts "\n"
      end
    end

    def load_directory(path)
      status("loading samples: #{path}")
      queue = []
      count = 0
      raise error("#{path} not found") unless File.directory?(path)
      Dir.foreach(path) do |entry|
        if File.directory?(entry) == false
          p = File.join(path, entry)
          queue << p
          count += 1
        end
      end
      info("loaded #{count} samples")
      return queue
    end

    # tons of crappy wrappers for text output
    def error(msg)
      puts red(bold("[!] #{msg}"))
    end

    def pgreen(msg)
      puts green("#{msg}")
    end

    def pbwhite(msg)
      puts white(bold("#{msg}"))
    end

    def status(msg)
      puts blue("[*] #{msg}")
    end

    def info(msg)
      puts white("[-] #{msg}")
    end

  end # end of class
end # end of module
