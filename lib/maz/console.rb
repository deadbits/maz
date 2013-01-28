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
    #@@Database = Maz::Database.new
    @commands = [ "help", "report", "search", "recent", "exit", "quit", "load", "analyze",
      "cuckoo", "anubis", "vtotal", "threatx" ]

    def help_menu
      puts %{

        for full support, review the files in the 'docs' directory.

     :::General Commands:::
        help                       -   display this menu
      report [html/txt] [sample]   -   generate report on [sample]
      search [type] [data]         -   query db for [md5/name] of [data]
      recent [count]               -   show [count] most recent submissions
      delete [sample md5]          -   remove [sample] from database completely
       stats                       -   display database statistics
       clear                       -   clears the console screen
        exit                       -   shutdown the MAZ console
     
      :::Analysis Commands:::
        load [file/directory]      -   add [file] or [directory] to queue
     analyze [file]                -   analyze [file], report and submit to database
      cuckoo [sample]              -   spin up [sample] in Cuckoo instance
      anubis [sample]              -   submit [sample] to Anubis and get report 
      vtotal [sample]              -   submit [sample] to VirusTotal and get report
     threatx [sample]              -   query ThreatExpert for [sample]
      }
    end

    def initialize
      Core.new
      pbwhite("\tMalware Analysis Zoo ::: interactive console")
      pbwhite("\thttps://github.com/ohdae/maz - MAZ (c) 2013")
      pbwhite("\ttype 'help' to view all available commands.\n")
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
        elsif cmd.include?("search")
          type = cmd.split(" ")[1]
          query = cmd.split(" ")[2]
          if type == "md5"
            result = @@Database.search_md5(query)
            unless result == nil
              pbwhite("Search Results: ")
              pp result
            end
          elsif type == "name"
            result = @@Database.search_file(query)
            unless result == nil
              pbwhite("Search Results: ")
              pp result
            end
          end
        elsif cmd == "stats"
          @@Database.stats
        elsif cmd.include?("delete")
          entry = cmd.split(" ")[1].chomp
          status("removing database entry belonging to md5 hash: #{entry}")
          puts @@Database.delete_entry(entry)
        elsif cmd.include?("analyze")
          filename = cmd.split(" ")[1].chomp
          status("starting analysis of sample: #{filename}")
          sample, stored = @@Analyze.submit(filename)
          info("sample copied to storage directory: #{stored}")
          status("submitting to database ...")
          @@Database.create(sample)
          text_report(sample)
        elsif cmd.include?("load")
          path = cmd.split(" ")[1].chomp
          if File.directory?(path)
            @queue = load_directory(path)
          elsif File.exist?(path)
            status("loading sample: #{path}")
            @queue = path
          end
        else
          error("command #{cmd} is not a valid entry.")
        end
      end
    end
  end
end


