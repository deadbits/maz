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

require 'digest/md5'
require 'digest/sha1'

module Maz
  class Analyze < Maz::External

    @network_strings = [ "IRC", "http", "InternetReadFile", "Connect", "JOIN", "NICK",
      "port", "host", "PING", "PONG", "gethostbyname", "Socket", "bind", "listen", "download",
      ".exe", "Request" ]

    @system_strings = [ "OpenProcess", "VirtualAllocEx", "StartService", "CreateRemoteThread",
      "CreateProcess", "WinExec", "ReadProcessMemory", "ShellExecute", "cmd.exe", "StartService",
      "FindWindow", "shell32", "CreateMutex", "RegCreate", "RegSet", "RegOpenKey", "IsDebuggerPresent",
      "HKEY", "Admin"]

    def is_binary?(file)
      if File.exists?(file) && File.executable?(file)
        return true
      else
        return false
      end
    end

    def strings(file)
      result = {}
      output = `strings -a -tx #{file}`.split("\n")
      output.each do |line|
        offset = line.split(" ")[0].to_s
        ascii = line.split(" ")[1].to_s
        result["#{offset}"] = "#{ascii}"
      end
      return result
    end

    def store_file
      storage = "#{ENV['HOME']}/maz/samples"
      if File.directory?(storage)
        full = "#{storage}/#{@info[:file_name].chomp(File.extname(@info[:file_name]))}"
        path = "#{full}_#{@info[:md5_hash]}"
        Dir.mkdir(path)
        `cp #{@info[:location]} #{path}`
        return path
      end
    end

    def static(file_name)
      @info = {
        :file_name => File.basename(file_name),
        :file_type => `file -b #{file_name}`.chomp,
        :file_size => File.size?(file_name),
        :location => file_name,
        :time => Time.now,
        :md5_hash => Digest::MD5.hexdigest(File.read(file_name)),
        :sha1_hash => Digest::SHA1.hexdigest(File.read(file_name)),
        :strings => strings(file_name),
        :shadow => shadow_query(Digest::MD5.hexdigest(File.read(file_name)))
      }
    end

    def submit(file_name)
      sample = static(file_name)
      stored = store_file
      return sample, stored
    end
    
    def scan_strings
      found = {}
      lines = File.open(@info[:location], "r:ASCII-8BIT")
      lines.readlines.each do |line|
        @network_strings.each do |n|
          if line.include?(n)
            info("found string #{n} in sample #{@info[:file_name]}")
            found[n] = line.to_s
          end
        end
        @system_strings.each do |s|
          if line.include?(s)
            info("found string #{n} in sample #{@info[:file_name]}")
            found[s] = line.to_s
          end
        end
      end
      unless found == {}
        @info[:ascii_sigs] = found
      end
    end

  end
end


