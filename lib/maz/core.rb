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
      unless File.directory?("#{ENV['HOME']}/maz")
        puts "This looks like your first time running MAZ. Starting setup ..."
        status("creating environment directories ...")
        Dir.mkdir("#{ENV['HOME']}/maz")
        Dir.mkdir("#{ENV['HOME']}/maz/samples")
        Dir.mkdir("#{ENV['HOME']}/maz/logs")
        info("environment created.")
      end
    end

    def write!(filename, data)
      File.open(filename, 'w') { |fout| fout.write(data) }
    end

    def time
      now = Time.new
      return now.utc.strftime("%Y-%m-%d %H:%M:%S")
    end

    def shutdown
      status("shutting down MAZ ...")
      exit
    end

    def pass
      ;
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

  end
end
