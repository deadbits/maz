#!/usr/bin/env ruby
##
# Malware Analysis Zoo
# name: console.rb
# desc: this is the console interface
# to MAZ. you can analyze all the malwares
# from here :D
##

require 'readline'
require File.expand_path("#{File.dirname __FILE__}" + "/../maz")

module Maz
  class Console < Maz::Core
    @@Analyze = Maz::Analyze.new
    @commands = [ "help", "report", "search", "recent", "exit", "quit", "load", "analyze",
      "anubis", "vtotal", "remote", "shadow" ].sort

    def help_menu
      puts %{

     :::General Commands:::
        help                       -   display this menu
         web                       -   launch web interface
      remote                       -   configure MAZ for remote MongoDB instance
      report [html/txt] [sample]   -   generate report on [sample]
      search [type] [data]         -   query db for [md5/sha1/name] of [data]
      recent                       -   show most recent submission
      delete [sample md5]          -   remove [sample] from database completely
       stats                       -   display database statistics
       clear                       -   clears the console screen
        exit                       -   shutdown the MAZ console

      :::Analysis Commands:::
        load [file/directory]      -   add [file] or [directory] to queue
     analyze <queue> [file]        -   analyze [file], report and submit to database
        queue                      -   view queued sample list
         tags                      -   tag management
      anubis [sample]              -   submit [sample] to Anubis
      vtotal [sample]              -   submit [sample] to VirusTotal
     wepawet [sample]              -   submit [sample] to Wepawet
    lastline [sample]              -   submit [sample] to Lastline
      }
    end

    def search(input)
      type, query = input.split(" ")[1], input.split(" ")[2]
      if type.downcase == "md5"
        result = @@Database.search("md5", query, true)
      elsif type.downcase == "sha1"
        result = @@Database.search("sha1", query, true)
      elsif type.downcase == "name"
        result = @@Database.search("file", query, true)
      else
        error("#{type} is not a valid search type")
      end
      unless result == nil
        pbwhite("Search Results: ")
        if result == false
          puts "no results found for #{type} => #{query}"
        else
          pp result
        end
      end
    end

    def queue_add(path)
      @queue = []
      path = path.split(" ")[1].chomp
      if File.directory?(path)
        pbwhite("#{path} is a directory. All files in this location will be added to the queue.")
        @queue = load_directory(path)
      elsif File.exist?(path)
        status("added sample #{path} to queue ...")
        @queue << path
      end
    end

    def initialize
      Core.new
      pbwhite("\tMalware Analysis Zoo ::: interactive console")
      pbwhite("\ttype 'help' to view all available commands.\n")

      stty_save = `stty -g`.chomp
      trap("INT") { system("stty", stty_save); exit }
      prompt = white(bold("maz >> "))

      while cmd = Readline.readline("#{prompt}", true).chomp
        if cmd == "exit"
          shutdown
        elsif cmd == "quit"
          shutdown
        elsif cmd == "help"
          help_menu
        elsif cmd == "clear"
          system("clear")
        elsif cmd == "queue"
          if @queue
            pbwhite("Current Sample Queue: ")
            @queue.each do |f|
              puts f
            end
          else
            info("the file queue is empty")
          end

        elsif cmd == "tags"
          no_feature("tag management")
          #status("entering tag management")
          #manage_tags

        elsif cmd == "recent"
          last = @@Database.view_last
          pbwhite("Last Submission: ")
          pp last

        elsif cmd.include?("search")
          search(cmd)

        elsif cmd == "stats"
          @@Database.stats

        elsif cmd.include?("delete")
          entry = cmd.split(" ")[1].chomp
          status("removing database entry belonging to md5 hash: #{entry}")
          puts @@Database.delete_entry(entry)

        elsif cmd.include?("analyze")
          if cmd.include?("queue")
            @queue.each do |sample|
              @@Analyze.submit(sample)
            end
          else
            file_name = cmd.split(" ")[1]
            @@Analyze.submit(file_name)
          end

        elsif cmd.include?("load")
          queue_add(cmd)

        elsif cmd.include?("lastline")
          no_feature("lastline")

        elsif cmd.include?("vtotal")
          no_feature("vtotal")

        elsif cmd.include?("wepawet")
          no_feature("wepawet")

        elsif cmd.include?("anubis")
          no_feature("anubis")

        elsif cmd == "web"
          no_feature("web")

        else
          error("command #{cmd} is not a valid entry.")
        end

      end
    end
  end
end


