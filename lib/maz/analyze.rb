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
require 'net/http'
require 'socket'
require 'nokogiri'
require 'open-uri'
require 'crack'
require 'json'
#require 'yara'

module Maz
  class Analyze < Maz::Core

    def is_binary?(file)
      if File.exists?(file) && File.executable?(file)
        return true
      else
        return false
      end
    end

    #def yara
    #  results = []
    #  rules = []
    #  rules.each do |r|
    #    rule = Yara::Rules.new
    #    rule.compile_string(r)
    #    rule.scan_file(@sample[:location]) do |match|
    #      results << (match.rule).to_s
    #    end
    #  end
    #end

    #def strings(file)
    #  result = {}
    #  output = `strings -a -t x #{file}`.split("\n")
    #  output.each do |line|
    #    offset = line.split(" ")[0].to_s
    #    ascii = line.split(" ")[1].to_s
    #    result["#{offset}"] = "#{ascii}"
    #  end
    #  return result
    #end

    def store_file
      storage_path = "#{ENV['HOME']}/maz/samples"
      if File.directory?(storage_path)
        stripped = "#{storage_path}/#{@sample[:file_name].chomp(File.extname(@sample[:file_name]))}"
        new_path = "#{stripped}_#{@sample[:md5_hash]}"
        if File.directory?(new_path)
          return false
        end
        Dir.mkdir(new_path)
        `cp #{@sample[:location]} #{new_path}`
        return new_path
      end
    end

    def static(file_name)
      @sample = {
        :file_name => File.basename(file_name),
        :file_type => `file -b #{file_name}`.chomp,
        :file_size => File.size?(file_name),
        :location => file_name,
        :time => time,
        :md5_hash => Digest::MD5.hexdigest(File.read(file_name)),
        :sha1_hash => Digest::SHA1.hexdigest(File.read(file_name)),
        #:strings => strings(file_name),
        :shadow => shadow_query(Digest::MD5.hexdigest(File.read(file_name))),
        :tags => []
      }
    end

    def submit(file_name)
      if File.exist?(file_name)
        status("starting analysis of sample: #{file_name}")
        static(file_name)
        stored = store_file
        if stored == false
          error("sample all ready exists in storage location!\ndid you all ready analyze this file?")
          return false
        else
          status("sample copied to storage location: #{stored}")
          status("submitting to database")
          @@Database.insert(@sample)
        end
      else
        error("file #{file_name} cannot be found")
      end
    end

    def shadow_query(md5_hash)
      url = URI.parse("http://innocuous.shadowserver.org/api/?query=#{md5_hash}")
      request = Net::HTTP::Get.new("#{url.path}?#{url.query}")
      http = Net::HTTP.new(url.host, url.port)
      req = http.request(request)
      unless req.body.include?("No match found")
        result = req.body
        lines = result.split("\n")
        md5, sha1, first, last, type, ssdeep = lines[0].gsub(/\"/,'').split(/,/)
        av_results = JSON.parse(lines[1])
        @shadow = {
          :md5 => md5,
          :sha1 => sha1,
          :first => first,
          :last => last,
          :type => type,
          :ssdeep => ssdeep,
          :avres => av_results
        }
        return @shadow
      end
      return nil
    end

    def cymru_query(md5_hash)
      @cymru = []
      connect = TCPSocket.new("hash.cymru.com", 43)
      connect.write("begin\nverbose\n#{md5_hash}\nend\n")
      connect.each_line do |line|
        unless line =~ /^#/
          @cymru << line.chomp.split(/\s+/,3)
        end
      end
      return @cymru_result
    end

  end
end


