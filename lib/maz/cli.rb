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

require File.expand_path("#{File.dirname __FILE__}" + "/../maz")
require 'trollop'

module Maz
  class CLI < Maz::Core
    @@Database = Maz::Database.new
    @@Analyze = Maz::Analyze.new

    def initialize
      @opts = Trollop::options do
        version = "beta version 0.5 (c) 2013 - ams"
        banner <<-EOS
      Malware Analysis Zoo :: command line interface
      website:  https://github.com/ohdae/maz

      maz-cli.rb is for quick analysis and sample submissions. all samples
      you submit through this script will be analyzed, stored in the maz database
      and reports will be generated.

      Usage: maz-cli [options] [args]
      Options:
      EOS
        opt :file, "Sample file path to analyze and submit", :type => String
        opt :report, "Display text report after analysis", :default => true
        opt :query, "Search MAZ database for MD5 hash", :type => String
        opt :recent, "Display last [count] submissions", :type => Integer
        opt :stats, "Show statistics on indexed samples and database entries", :default => false
        opt :web, "Launch MAZ web engine", :default => false
        opt :host, "Remote MongoDB host for sample storage", :type => String
        opt :port, "Remote MongoDB port for sample storage", :type => Integer
      end

      if @opts[:web]
        no_feature("web")

      elsif @opts[:host]
        if @opts[:port]
          no_feature("remote mongodb instance")
        end

      elsif @opts[:file]
        if File.exists?(@opts[:file])
          @@Analyze.submit(@opts[:file])
        else
          Trollop::die :file, "does not seem to exist"
        end

      elsif @opts[:recent]
        last = @@Database.view_last
        pbwhite("\nLast Submission: ")
        pp last

      elsif @opts[:query]
        result = @@Database.search_md5(@opts[:query])
        unless result == nil
          pbwhite("\nSearch Results: ")
          pp result
        end

      elsif @opts[:stats]
        @@Database.stats
      end

    end

  end
end
