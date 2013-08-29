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
      "cuckoo", "anubis", "vtotal", "threatx" ].sort

    def help_menu
      puts %{

        for full support, review the files in the 'docs' directory.

     :::General Commands:::
        help                       -   display this menu
      report [html/txt] [sample]   -   generate report on [sample]
      search [type] [data]         -   query db for [md5/sha1/name] of [data]
      recent                       -   show most recent submission
      delete [sample md5]          -   remove [sample] from database completely
       stats                       -   display database statistics
       clear                       -   clears the console screen
        exit                       -   shutdown the MAZ console
     
      :::Analysis Commands:::
        load [file/directory]      -   add [file] or [directory] to queue
     analyze [file]                -   analyze [file], report and submit to database
         tag [sample] [tags]       -   add custom tags to [sample] in db. use comma separated tags
      cuckoo [sample]              -   spin up [sample] in Cuckoo instance
      anubis [sample]              -   submit [sample] to Anubis and get report 
      vtotal [sample]              -   submit [sample] to VirusTotal and get report
     threatx [sample]              -   query ThreatExpert for [sample]
      }
    end

    def search(input)
      type, query = input.split(" ")[1], input.split(" ")[2]
      if type.downcase == "md5"
        result = @@Database.search_md5(query)
      elsif type.downcase == "sha1"
        result = @@Database.search_sha1(query)
      elsif type.downcase == "name"
        result = @@Database.search_name(query)
      else
        error("#{type} is not a valid search type")
      end
      unless result == nil
        pbwhite("Search Results: ")
        pp result
      end
    end

    def analyze(input)
      file = input.split(" ")[1].chomp
      if File.exist?(file)
        status("starting analysis of sample: #{file}")
        sample, stored = @@Analyze.submit(file)
        info("sample copied to storage directory: #{stored}")
        status("submitting to database ...")
        @@Database.create(sample)
        text_report(sample)
      else
        error("file #{file} cannot be found")
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

    def manage_tags(sample, tags)
      # placeholder for tag management function
      # might add this function to either the core
      # or database.rb library since it can be used
      # through-out the application
      nil
    end

    def initialize
      Core.new
      pbwhite("\tMalware Analysis Zoo ::: interactive console")
      pbwhite("\thttps://github.com/ohdae/maz - MAZ (c) 2013")
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

        elsif cmd.include?("tag")
          #pbwhite("This feature lets you add custom tags to samples stored in the MAZ database.")
          #pbwhite("Tags are a great way to identify, and later search for, samples.")
          #pbwhite("Enter your tags after the sample's name or md5 hash in a comma separated format.")
          #pbwhite("example: tag flashback.exe flashback, osx, backdoor")
          #sample = cmd.split(" ")[1]
          puts "feature not yet implemented."

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
          analyze(cmd)
        
        elsif cmd.include?("load")
          queue_add(cmd)

        else
          error("command #{cmd} is not a valid entry.")
        end
      
      end
    end
  end
end


