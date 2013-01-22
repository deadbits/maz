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
require File.expand_path("#{File.dirname __FILE__}/database")
#require File.expand_path("#{File.dirname __FILE__}/lib/maz")
include Term::ANSIColor

ascii = ""
ascii += "\n\n"                                        
ascii += "\n\t`7MMM.     ,MMF'      db      MMM###AMV "
ascii += "\n\t  MMMb    dPMM       ;MM:     M'   AMV  "
ascii += "\n\t  M YM   ,M MM      ,V^MM.    '   AMV   "
ascii += "\n\t  M  Mb  M' MM     ,M  `MM       AMV    "
ascii += "\n\t  M  YM.P'  MM     AbmmmqMA     AMV   , "
ascii += "\n\t  M  `YM'   MM    A'     VML   AMV   ,M "
ascii += "\n\t.JML. `'  .JMML..AMA.   .AMMA.AMVmmmmMM "
ascii += "\n\t  malware analysis zoo => beta version  "
ascii += "\n\t      https://github.com/ohdae/maz      "
ascii += "\n\n"

module Maz
  class Core

    def initialize
      status("checking MAZ environment ...")
      unless File.directory?("#{ENV['HOME']}/maz")
        puts "This looks like your first time running MAZ. Starting setup ..."
        status("creating environment directories ...")
        Dir.mkdir("#{ENV['HOME']}/maz")
        Dir.mkdir("#{ENV['HOME']}/maz/storage")
        Dir.mkdir("#{ENV['HOME']}/maz/logs")
        `touch #{ENV['HOME']}/.maz_history`
        info("environment created.")
      end
      info("environment ok.\n")
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

    def is_binary?(file)
      if File.exists?(file) and File.executable?(file)
        return true
      else
        return false
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

    def pblue(msg)
      puts blue("#{msg}")
    end

    def pred(msg)
      puts red("#{msg}")
    end

    def pgreen(msg)
      puts green("#{msg}")
    end

    def pbwhite(msg)
      puts white(bold("#{msg}"))
    end

    def status(msg)
      puts blue(bold("[~] #{msg}"))
    end

    def info(msg)
      puts white(bold("[*] #{msg}"))
    end

  end # end of class
end # end of module
