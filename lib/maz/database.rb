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

require 'mongo'
require 'rubygems'
require 'securerandom'

module Maz
  class Database

    def initialize
      # start new mongodb connection
      # make sure our database and collections exist.
      # make sure we are in the 'storage' collection.
      @mongo = Mongo::Connection.new
      @mazdb = @mongo.db("maz_db")
      @report_db = @mazdb["reports"]
      @store_db = @mazdb["storage"]
    end

    def close
      @store_db.connection.close
      @report_db.connection.close
    end

    def db_exists?
      # check if we initialized our db connection
      # and are currently in the 'storage' collection.
      if @mazdb["storage"]
        return true
      else
        return false
      end
    end

    def create(data)
      # entry should come in with this format
      # data = {
        #:file_name => :file_name,
        #:file_type => :file_type,
        #:file_size => :file_size,
        #:submitted => :time,
        #:md5_hash  => :md5_hash,
        #:sha1_hash => :sha1_hash,
        #:shadow => {
          #:md5  => @shadow[:md5],
          #:sha1 => @shadow[:sha1],
          #:first => @shadow[:first],
          #:last  => @shadow[:last],
          #:type  => @shadow[:type],
          #:ssdeep => @shadow[:ssdeep],
          #:avres => @shadow[:avres]
        #} }
      entry_id = @store_db.insert(entry)
      puts "[*] entry accepted for id: #{entry_id}"
    end

    def count_all
      count = @store_db.count.to_i
      return count
    end

    def remove(query)
      return @store_db.remove(query)
    end

    def stats
      Core.pgreen("\n\t[ Database Statistics ]")
      Core.pbwhite("  current time:\t#{Time.now}")
      Core.pbwhite(" total entries:\t#{Database.count_all}")
      Core.pbwhite("   most recent:\t#{Database.view_last}")
      Core.pbwhite("database stats: ")
      @mazdb.stats().each_pair { |k,v| puts "#{k} : #{v}" }
      Core.pbwhite("storage collection: ")
      @store_db.stats().each_pair { |k,v| puts "#{k} : #{v}" }
      puts "\n"
    end

    def view_last
      result = @store_db.find_one
      return result.inspect
    end

    def view_all
      # returns all records inside the 'storage' collection
      all = {}
      @store_db.find.each do |item|
        puts item.inspect
      end
      return all
    end

    def search_md5(hash)
      # puts "searching for MD5 hash #{query}"
      result = @store_db.find("md5_hash" => "#{hash}")
      unless result == []
        return result.inspect
      end
      return nil
    end

    def search_sha1(hash)
      result = @store_db.find("sha1_hash" => "#{hash}")
      unless result == []
        return result.inspect
      end
      return nil
    end

    def search_file(file_name)
      result = @store_db.find("file_name" => "#{file_name}")
      unless result == []
        return result.inspect
      end
      return nil
    end

  end
end

