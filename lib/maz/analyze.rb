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

require File.expand_path("#{File.dirname __FILE__}/core")
require File.expand_path("#{File.dirname __FILE__}/external")
require 'digest/md5'
require 'digest/sha1'

module Maz
  class Analyze

    def is_binary?(file)
      if File.exists?(file) && File.executable?(file)
        return true
      else
        return false
      end
    end

    def static(file_name)
      @info = {
        :file_name => file_name,
        :file_type => `file #{file_name}`.chomp,
        :file_size => File.size?(file_name),
        :time => Time.now,
        :md5_hash => Digest::MD5.hexdigest(File.read(file_name)),
        :sha1_hash => Digest::SHA1.hexdigest(File.read(file_name)),
      }
    end

    def xor(data)
      matches = []
      pattners = [ /http:\/\//, /ftp:\/\//, /\.dll/, /\.exe/ ]
      0.upto(255) do |key|
        decoded = data.unpack("C*").map { |e| e ^ key }.pack("C*")
        matching = []
        patterns.each do |p|
          matching << p.source if decoded.match(p)
        end
        unless matching.empty?
          matches << { :key => key, :patterns => matching, :data => decoded }
        end
      end
      return matches
    end

    def network_strings(line)
      count = 0
      calls = ["IRC", "BOT", "JOIN", "flood", "ddos", "NICK", "SERVER", "socket", 
        "MOTD", "QUIT", "GET", "MODE", "QUIT", "PONG", "PING"]
      calls.each do |c|
        if line =~ /#{c}/
          count += 1
          @info[:suspicious] = line
        end
      end
      info("found #{count} suspicious network strings!") unless count == 0
    end

    def system_strings
      count = 0
      calls = ["Socket", "http://", "CreateFile.*WRITE", "CreateMutex", "KERNEL32.CreateProcess",
        "ws2_32.bind", "shdocvw", "advapi32.RegCreate", "IsDebuggerPresent", "FindWindow", "call shell32"]
      calls.each do |c|
        if line =~ /#{c}/
          count += 1
          @info[:suspicious] = line 
        end
      end
      info("found #{count} suspicious system strings!") unless count == 0
    end

    def string_analysis
      if self.is_binary?(@info[:file_name])
        lines = File.new(@info[:file_name], "r:ASCII-8BIT")
        lines.readlines.each do |line|
          network_strings(line)
          registry_strings(line)
          system_strings(line)
        end
      end
    end

    def get_shadow(hash)
      # query and retrieve shadowserver info
      external = Maz::External.new
      return external.shadow_query(hash)
    end

    def get_anubis
      # submit and retrieve anubis report
      nil
    end

    def get_threatex(hash)
      external = Maz::External.new
      return external.threatx_query(hash)
    end

  end
end


