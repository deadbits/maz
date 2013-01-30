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
$:.unshift(File.dirname(__FILE__))

require 'mongo'
require 'rubygems'
require 'securerandom'
require 'pp'

module Maz
  class Database < Maz::Core

    def initialize
      # start new mongodb connection
      # make sure our database and collections exist.
      # make sure we are in the 'storage' collection.
      #status("initializing mongodb ...")
      @mongo = Mongo::Connection.new
      @mazdb = @mongo.db("maz_db")
      @store_db = @mazdb["storage"]
    end

    def db_exists?
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
      entry_id = @store_db.insert(data)
      status("entry accepted for id: #{entry_id}")
    end

    def count_all
      count = @store_db.count.to_i
      return count
    end

    def stats
      pgreen("\n\t[ Database Statistics ]")
      pbwhite("\ntotal entries: ")
      pp count_all
      pbwhite("\nmost recent: ")
      pp view_last
      pbwhite("\ndatabase stats: ")
      @mazdb.stats().each_pair { |k,v| puts "#{k} : #{v}" }
      pbwhite("\nstorage collection: ")
      @store_db.stats().each_pair { |k,v| puts "#{k} : #{v}" }
      puts "\n"
    end

    def view_last
      result = @store_db.find_one.to_a
      return result
    end

    def view_all
      all = {}
      @store_db.find.each do |item|
        puts item.inspect
      end
      return all
    end

    def delete_entry(type, query)
      if type == "file"
        result = @store_db.remove("file_name" => "#{query}")
      elsif type == "md5"
        result = @store_db.remove("md5_hash" => "#{query}")
      elsif type == "sha1"
        result = @store_db.remove("sha1_hash" => "#{query}")
      end
      return result
    end

    def search(type, query)
      # NOTES
      # raw mongo shell query for excluding fields from search results is:
      # db.products.find( { qty: { $gt: 25 } }, { _id: 0, qty: 0 } )
      # not sure if I can do the same via mongo gem but it should look something
      # like this: @store_db.find("file_name" => "#{query}", "_id" => 0, "strings" => 0)
      if type == "file"
        result = @store_db.find("file_name" => "#{query}").to_a
      elsif type == "md5"
        result = @store_db.find("md5_hash" => "#{query}").to_a
      elsif type == "sha1"
        result = @store_db.find("sha1_hash" => "#{query}").to_a
      end
      return result
    end

  end
end

