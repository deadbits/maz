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

#require File.expand_path("#{File.dirname __FILE__}/lib/maz")
require 'trollop'

module Maz
  class CLI
    Core = Maz::Core.new
    Analyze = Maz::Core.new
    Database = Maz::Database.new

    def initialize
      opts = Trollop::options do
        version = "beta version 0.5 (c) 2013 - Adam M. Swanda"
        banner <<-EOS
      Malware Analysis Zoo :: command line interface 
      website:  https://github.com/ohdae/maz

      maz-cli.rb is for quick analysis and sample submissions. all samples
      you submit through this script will be analyzed, stored in the maz database
      and reports will be generated and saved. for more fine tuned control over
      your maz experience, check out the maz-console.rb application.

      Usage: maz-cli [options] [args]
      Options:
      EOS
        opt :file, "Sample file path to analyze and submit", :type => String
        opt :report, "Display text report after analysis", :default => true
        opt :query, "Search MAZ database for MD5 hash", :type => String
        opt :count, "Display last [count] submissions", :type => Integer
        opt :stats, "Show statistics on indexed samples and database entries", :default => false
      end
      # perform some quick error checks on our options and arguments
      if opts[:file]
        unless File.exists?(opts[:file])
          Trollop::die :file, "does not seem to exist"
        end
      elsif opts[:count] and opts[:count].to_i <= 0
        Trollop::die :count, "must be a positive number"
      elsif opts[:file]
        submit(opts[:file])
      elsif opts[:query]
        output = Database.search_md5(opts[:query])
        if output != nil
          Core.pgreen("\tSearch Results: ")
          output.each do |entry|
            Core.pbwhite("#{entry.inspect}")
          end
        end
      elsif opts[:stats]
        Database.stats
      end
    end

    def submit(filename)
      Core.status("starting analysis of sample: #{filename}")
      @sample = Analyze.static(filename)
      @sample[:shadow] = Analyze.get_shadow(@sample[:md5_hash])
      Core.status("analysis complete. submitting to database ...")
      Database.create(@sample)
      report
    end

    def report
      Core.pbwhite("\n\t[ Analysis Report ]")
      puts "File Name:\t#{@sample[:file_name]}"
      puts "File Type:\t#{@sample[:file_type]}"
      puts "File Size:\t#{@sample[:file_size]}"
      puts "Submitted:\t#{@sample[:time]}"
      puts " MD5 Hash:\t#{@sample[:md5_hash]}"
      puts "SHA1 Hash:\t#{@sample[:sha1_hash]}"
      puts "\n"
      #unless @sample[:shadow] == nil
      #  puts "First Seen:\t#{@sample[:shadow][:first]}"
      #  puts " Last Seen:\t#{@sample[:shadow][:last]}"
      #  puts " File Type:\t#{@sample[:shadow][:type]}"
      #  puts "Fuzzy Hash:\t#{@sample[:shadow][:ssdeep]}"
      #  Core.pbwhite("\t[ Anti-Virus ]")
      #  @sample[:shadow][:avres].each { |av| puts "#{av}"}
      #  puts "\n"
      #end
    end

  end
end












